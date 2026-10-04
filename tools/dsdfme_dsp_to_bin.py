#!/usr/bin/env python3
# FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
# Copyright (C) 2026 FSP-Labs
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.
"""
Convert DSD-FME -Q DSP structured output + stderr log into FSP.DMRCrack .bin payload file.

The log file provides PI header metadata (ALG, KID, MI).  Each PI header
carries the MI for one superframe (6 consecutive voice bursts).  Between
superframes the MI advances by 32 LFSR steps.

Usage:
    python tools/dsdfme_dsp_to_bin.py --dsp DSP_FILE --out OUTPUT.bin --log LOG_FILE
"""

import argparse
import pathlib
import re
import sys
from typing import Optional

VOICE_TYPE = "10"

# MOTOTRBO PI header: carries an inline "Slot N" and a 32-bit MI.
PI_RE = re.compile(
    r"Slot\s+([12]).*?ALG ID:\s*([0-9A-Fa-f]{2});\s*KEY ID:\s*([0-9A-Fa-f]{2});\s*MI\(32\):\s*([0-9A-Fa-f]{8})",
    re.IGNORECASE,
)

# Hytera Enhanced PI header ("DMR PI H- ... MI(40): XXXXXXXXXX"): 40-bit MI, no
# inline slot -- the slot comes from the surrounding bracketed sync marker.
HYTERA_PI_RE = re.compile(
    r"ALG ID:\s*([0-9A-Fa-f]{2});\s*KEY ID:\s*([0-9A-Fa-f]{2});\s*MI\(40\):\s*([0-9A-Fa-f]{10})",
    re.IGNORECASE,
)

# Active slot marker in a sync line, e.g. "[SLOT1]" / "[slot2]".
SYNC_SLOT_RE = re.compile(r"\[slot([12])\]", re.IGNORECASE)

# Inline "Slot N" prefix on a PI header line.
INLINE_SLOT_RE = re.compile(r"Slot\s+([12])", re.IGNORECASE)

# Late-entry MI recovered from the voice superframe's embedded signalling, e.g.
# "Slot N PI/LFSR and Late Entry MI Mismatch - AAAA : BBBB (CRC OK)". BBBB passed
# CRC and is the true MI when the PI header's own MI field decoded to zero.
LATE_ENTRY_RE = re.compile(
    r"Slot\s+([12]).*?Late Entry MI Mismatch\s*-\s*[0-9A-Fa-f]+\s*:\s*([0-9A-Fa-f]+)\s*\(CRC OK\)",
    re.IGNORECASE,
)

DSP_RE = re.compile(r"^\s*(\d+)\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]+)\s*$")


def dmr_mi_lfsr_step(mi: int, steps: int = 1) -> int:
    """Advance MI by `steps` LFSR iterations (poly x^32+x^4+x^2+1, taps {31,3,1})."""
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1
        mi = ((mi << 1) & 0xFFFFFFFF) | bit
    return mi


def dmr_mi_lfsr_reverse(mi: int, steps: int = 1) -> int:
    """Exact inverse of dmr_mi_lfsr_step: step the MI LFSR backward. Used to
    recover the MI of voice bursts decoded BEFORE the first PI header."""
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        b31 = ((mi & 1) ^ ((mi >> 4) & 1) ^ ((mi >> 2) & 1)) & 1
        mi = ((mi >> 1) & 0x7FFFFFFF) | (b31 << 31)
    return mi


def superframe_start_kind(line: str) -> int:
    """Voice superframe-START marker classifier (see the C converter's twin).
    Repeater/TDMA logs 'VC1'[*] per superframe; simplex/MS logs one bare 'VC*'.
    Returns 1 (repeater start), 2 (simplex start), or 0."""
    if "VC1" in line:
        return 1
    i = line.find("VC")
    while i >= 0:
        if i + 2 < len(line) and line[i + 2] == "*":
            return 2
        i = line.find("VC", i + 2)
    return 0


_HYT_TAPS = (0x12, 0x24, 0x48, 0x22, 0x14)


def hytera_mi_lfsr_step(mi_value: int) -> int:
    """Advance a 40-bit Hytera EP MI by one superframe. Five independent 8-bit
    Galois LFSRs (one per MI byte, own tap), stepped once per superframe --
    verbatim from DSD-FME (audio_work) dmr_pi.c hytera_lfsr()."""
    mi = [(mi_value >> 32) & 0xFF, (mi_value >> 24) & 0xFF, (mi_value >> 16) & 0xFF,
          (mi_value >> 8) & 0xFF, mi_value & 0xFF]
    for i in range(5):
        bit = (mi[i] >> 7) & 1
        mi[i] = (mi[i] << 1) & 0xFF
        if bit:
            mi[i] ^= _HYT_TAPS[i]
        mi[i] |= bit
    out = 0
    for b in mi:
        out = (out << 8) | b
    return out


def parse_log_pi_sequence(log_path: pathlib.Path):
    """Parse all PI headers from the log IN ORDER, returning per-slot lists.

    Returns dict: slot -> list of {"alg": int, "kid": int, "mi": int}.
    The first entry is the initial PI (superframe 0), each subsequent entry
    is for the next superframe.
    """
    pi_seq = {1: [], 2: []}
    first_sf = {1: 0, 2: 0}   # true superframe index of each slot's first PI

    if not log_path or not log_path.exists():
        return pi_seq, first_sf

    cur_slot = 0  # last active slot seen in a sync line (for Hytera PI attribution)
    rep_sf = {1: 0, 2: 0}     # repeater superframe starts ("VC1")
    simp_sf = {1: 0, 2: 0}    # simplex superframe markers ("VC*")

    def cur_sf(slot):
        # True superframe index of a PI seen right now, from the superframe-start
        # markers counted so far. DSD-FME often locks onto voice several superframes
        # before it decodes a clean PI, so PIs are usually NOT at superframe 0.
        # Repeater's "VC1" precedes the mid-superframe PI (subtract 1); simplex's
        # "VC*" follows it (use as-is).
        r, sp = rep_sf[slot], simp_sf[slot]
        return (r - 1) if r else sp

    def pin_first(slot):
        if not pi_seq[slot]:  # about to append this slot's FIRST PI
            first_sf[slot] = cur_sf(slot)

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sm = SYNC_SLOT_RE.search(line)
            if sm:
                cur_slot = int(sm.group(1))

            k = superframe_start_kind(line)
            if k:
                vs = cur_slot if cur_slot else 1   # simplex/MS -> slot 1
                if k == 1:
                    rep_sf[vs] += 1
                elif k == 2:
                    simp_sf[vs] += 1

            m = PI_RE.search(line)
            if m:
                slot = int(m.group(1))
                alg = int(m.group(2), 16)
                kid = int(m.group(3), 16)
                mi = int(m.group(4), 16)
                pin_first(slot)
                pi_seq[slot].append({"alg": alg, "kid": kid, "mi": mi, "sf": cur_sf(slot)})
                continue

            # Hytera Enhanced PI: 40-bit MI. Slot from the inline "Slot N" when
            # present (DSD-FME prints it), else the surrounding sync context.
            if "MI(40):" in line:
                hm = HYTERA_PI_RE.search(line)
                if hm:
                    sl = INLINE_SLOT_RE.search(line)
                    slot = int(sl.group(1)) if sl else cur_slot
                    if slot in (1, 2):
                        alg = int(hm.group(1), 16)
                        kid = int(hm.group(2), 16)
                        mi = int(hm.group(3), 16)
                        pin_first(slot)
                        pi_seq[slot].append({"alg": alg, "kid": kid, "mi": mi})
                continue

            # Backfill a zeroed PI MI from the CRC-OK late-entry recovery that
            # DSD-FME prints on the next line; otherwise the whole superframe is
            # scored with MI=0 (pure noise against the correct key).
            le = LATE_ENTRY_RE.search(line)
            if le:
                slot = int(le.group(1))
                mi = int(le.group(2), 16)
                lst = pi_seq[slot]
                if lst and lst[-1]["mi"] == 0:
                    lst[-1]["mi"] = mi

    return pi_seq, first_sf


def convert_dsp_to_bin(dsp_path: pathlib.Path, out_path: pathlib.Path, log_path: Optional[pathlib.Path]):
    pi_seq, first_sf = (parse_log_pi_sequence(log_path) if log_path
                        else ({1: [], 2: []}, {1: 0, 2: 0}))

    # Per-slot state: tracks current superframe index and burst count within SF
    slot_state = {}
    for slot in (1, 2):
        slot_state[slot] = {
            "pi_list": pi_seq[slot],
            "first_sf": first_sf[slot],  # superframe index of pi_list[0]
            "burst_count": 0,       # voice bursts emitted so far for this slot
        }

    total_lines = 0
    voice_lines = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with dsp_path.open("r", encoding="utf-8", errors="ignore") as fin, \
            out_path.open("w", encoding="ascii", newline="\n") as fout:
        for raw in fin:
            total_lines += 1
            m = DSP_RE.match(raw)
            if not m:
                continue

            slot = int(m.group(1))
            burst_type = m.group(2).upper()
            payload_hex = m.group(3).strip().upper()

            # Type 98 is the CACH, which DSD-FME emits before EVERY voice burst;
            # it is not a silence marker. Tagging the next burst SILENCE tagged
            # nearly every frame and pruned the correct key via the KPA filter.
            if burst_type == "98":
                continue
            if burst_type != VOICE_TYPE:
                continue
            if len(payload_hex) < 66:
                continue

            payload_hex = payload_hex[:66]
            line_out = payload_hex

            if slot in (1, 2):
                ss = slot_state[slot]
                pi_list = ss["pi_list"]

                if pi_list:
                    # Map this burst's superframe to the PI whose OWN superframe
                    # governs it: the most recent PI with sf <= sf_idx (PIs are in
                    # ascending superframe order), so each burst anchors to the PI of
                    # its own transmission. Indexing densely by (sf_idx - first_sf)
                    # breaks on multi-call captures: a boundary superframe carries two
                    # PIs (an outgoing C- plus the next call's H-), so a dense index
                    # runs one ahead per call and misaligns every later MI.
                    sf_idx = ss["burst_count"] // 6
                    gi = -1
                    for j, pe in enumerate(pi_list):
                        if pe["sf"] <= sf_idx:
                            gi = j
                        else:
                            break   # ascending: no later PI qualifies

                    if gi < 0:
                        # Before the first decoded PI: back-extrapolate from pi_list[0].
                        alg = pi_list[0]["alg"]
                        kid = pi_list[0]["kid"]
                        if alg == 0x02:
                            mi = pi_list[0]["mi"]  # Hytera 5-byte LFSR inverse not modeled
                        else:
                            mi = dmr_mi_lfsr_reverse(pi_list[0]["mi"], 32 * (pi_list[0]["sf"] - sf_idx))
                    elif pi_list[gi]["sf"] == sf_idx:
                        # Exact match. When two PIs share it (an outgoing C- then a
                        # new-call H-), prefer the FIRST -- it continues the call
                        # these bursts belong to; the H- governs from the next
                        # superframe. A lone H- start is the only entry and wins.
                        while gi > 0 and pi_list[gi - 1]["sf"] == sf_idx:
                            gi -= 1
                        mi = pi_list[gi]["mi"]
                        alg = pi_list[gi]["alg"]
                        kid = pi_list[gi]["kid"]
                    else:
                        # Gap between PIs: forward-extrapolate from the most recent
                        # one. A new-call H- re-anchors here, so extrapolation never
                        # crosses a call boundary. MOTOTRBO advances 32 LFSR steps/SF;
                        # Hytera steps its own 5-byte LFSR once per superframe.
                        gov = pi_list[gi]
                        extra_sfs = sf_idx - gov["sf"]
                        alg = gov["alg"]
                        kid = gov["kid"]
                        if alg == 0x02:
                            mi = gov["mi"]
                            for _ in range(extra_sfs):
                                mi = hytera_mi_lfsr_step(mi)
                        else:
                            mi = dmr_mi_lfsr_step(gov["mi"], 32 * extra_sfs)

                    if alg is not None:
                        line_out += f";ALG={alg:02X}"
                    if kid is not None:
                        line_out += f";KID={kid:02X}"
                    # 10 hex for a 40-bit Hytera MI, 8 hex for a 32-bit MOTOTRBO MI.
                    line_out += f";MI={mi:010X}" if mi > 0xFFFFFFFF else f";MI={mi:08X}"

                    ss["burst_count"] += 1

            fout.write(line_out + "\n")
            voice_lines += 1

    return total_lines, voice_lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert DSD-FME -Q DSP structured output into FSP.DMRCrack .bin payload file"
    )
    parser.add_argument("--dsp", required=True, help="Input DSD-FME DSP file produced with -Q")
    parser.add_argument("--out", required=True, help="Output .bin path for FSP.DMRCrack")
    parser.add_argument("--log", required=False, help="Optional DSD-FME stderr log (for ALG/KID/MI tags)")
    args = parser.parse_args()

    dsp_path = pathlib.Path(args.dsp)
    out_path = pathlib.Path(args.out)
    log_path = pathlib.Path(args.log) if args.log else None

    if not dsp_path.exists():
        print(f"ERROR: DSP file not found: {dsp_path}", file=sys.stderr)
        return 2

    total, voice = convert_dsp_to_bin(dsp_path, out_path, log_path)
    print(f"OK: parsed_lines={total} voice_bursts={voice} out={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
