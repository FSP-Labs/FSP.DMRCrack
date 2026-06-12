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

DSP_RE = re.compile(r"^\s*(\d+)\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]+)\s*$")


def dmr_mi_lfsr_step(mi: int, steps: int = 1) -> int:
    """Advance MI by `steps` LFSR iterations (poly x^32+x^4+x^2+1, taps {31,3,1})."""
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1
        mi = ((mi << 1) & 0xFFFFFFFF) | bit
    return mi


def parse_log_pi_sequence(log_path: pathlib.Path):
    """Parse all PI headers from the log IN ORDER, returning per-slot lists.

    Returns dict: slot -> list of {"alg": int, "kid": int, "mi": int}.
    The first entry is the initial PI (superframe 0), each subsequent entry
    is for the next superframe.
    """
    pi_seq = {1: [], 2: []}

    if not log_path or not log_path.exists():
        return pi_seq

    cur_slot = 0  # last active slot seen in a sync line (for Hytera PI attribution)
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sm = SYNC_SLOT_RE.search(line)
            if sm:
                cur_slot = int(sm.group(1))

            m = PI_RE.search(line)
            if m:
                slot = int(m.group(1))
                alg = int(m.group(2), 16)
                kid = int(m.group(3), 16)
                mi = int(m.group(4), 16)
                pi_seq[slot].append({"alg": alg, "kid": kid, "mi": mi})
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
                        pi_seq[slot].append({"alg": alg, "kid": kid, "mi": mi})

    return pi_seq


def convert_dsp_to_bin(dsp_path: pathlib.Path, out_path: pathlib.Path, log_path: Optional[pathlib.Path]):
    pi_seq = parse_log_pi_sequence(log_path) if log_path else {1: [], 2: []}

    # Per-slot state: tracks current superframe index and burst count within SF
    slot_state = {}
    for slot in (1, 2):
        slot_state[slot] = {
            "pi_list": pi_seq[slot],
            "burst_count": 0,       # voice bursts emitted so far for this slot
        }

    after_voice_hdr = {1: False, 2: False}

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

            if burst_type == "98":      # voice header: next voice burst is silence candidate
                if slot in (1, 2):
                    after_voice_hdr[slot] = True
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
                    # Determine which superframe this burst belongs to
                    sf_idx = ss["burst_count"] // 6
                    # burst_pos = ss["burst_count"] % 6  # not needed for MI

                    if sf_idx < len(pi_list):
                        # Use the PI MI for this superframe directly
                        mi = pi_list[sf_idx]["mi"]
                        alg = pi_list[sf_idx]["alg"]
                        kid = pi_list[sf_idx]["kid"]
                    else:
                        last_pi = pi_list[-1]
                        extra_sfs = sf_idx - (len(pi_list) - 1)
                        alg = last_pi["alg"]
                        kid = last_pi["kid"]
                        if alg == 0x02:
                            # Hytera EP advances the MI with its own LFSR (not modeled
                            # here); reuse the last decoded MI rather than extrapolate
                            # with the MOTOTRBO LFSR.
                            mi = last_pi["mi"]
                        else:
                            # MOTOTRBO: +32 LFSR steps per superframe.
                            mi = dmr_mi_lfsr_step(last_pi["mi"], 32 * extra_sfs)

                    if alg is not None:
                        line_out += f";ALG={alg:02X}"
                    if kid is not None:
                        line_out += f";KID={kid:02X}"
                    # 10 hex for a 40-bit Hytera MI, 8 hex for a 32-bit MOTOTRBO MI.
                    line_out += f";MI={mi:010X}" if mi > 0xFFFFFFFF else f";MI={mi:08X}"

                    ss["burst_count"] += 1

            is_silence = after_voice_hdr.get(slot, False)
            after_voice_hdr[slot] = False   # clear: only first burst after header
            if is_silence:
                line_out += ";SILENCE=1"

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
