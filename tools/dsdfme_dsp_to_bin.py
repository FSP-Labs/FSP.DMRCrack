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

PI_RE = re.compile(
    r"Slot\s+([12]).*?ALG ID:\s*([0-9A-Fa-f]{2});\s*KEY ID:\s*([0-9A-Fa-f]{2});\s*MI\(32\):\s*([0-9A-Fa-f]{8})",
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


def parse_log_pi_sequence(log_path: pathlib.Path):
    """Parse all PI headers from the log IN ORDER, returning per-slot lists.

    Returns dict: slot -> list of {"alg": int, "kid": int, "mi": int}.
    The first entry is the initial PI (superframe 0), each subsequent entry
    is for the next superframe.
    """
    pi_seq = {1: [], 2: []}

    if not log_path or not log_path.exists():
        return pi_seq

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PI_RE.search(line)
            if not m:
                continue
            slot = int(m.group(1))
            alg = int(m.group(2), 16)
            kid = int(m.group(3), 16)
            mi = int(m.group(4), 16)
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
                        # Extrapolate beyond available PIs using LFSR (+32 per SF)
                        last_pi = pi_list[-1]
                        extra_sfs = sf_idx - (len(pi_list) - 1)
                        mi = dmr_mi_lfsr_step(last_pi["mi"], 32 * extra_sfs)
                        alg = last_pi["alg"]
                        kid = last_pi["kid"]

                    if alg is not None:
                        line_out += f";ALG={alg:02X}"
                    if kid is not None:
                        line_out += f";KID={kid:02X}"
                    line_out += f";MI={mi:08X}"

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
