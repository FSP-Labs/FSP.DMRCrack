# Security & Acceptable Use

## Intended use

FSP.DMRCrack is a security-auditing and research tool. It recovers the 40-bit
RC4 key of DMR Enhanced Privacy from voice frames that have **already been
recorded**, and is designed and provided only for:

- auditing the strength of DMR Enhanced Privacy on radio systems **you own**;
- systems you are **explicitly authorized in writing** to test;
- recovering the key to **your own** communications; and
- security research and education.

It is **not** designed, intended, or provided for intercepting or decrypting
communications you are not authorized to access. To keep it to legitimate use the
tool has no radio-capture capability of its own: it does not tune, receive, or
record over the air, and ships with no SDR hardware. It operates only on a
recording you supply, and it requires the operator to affirm authorized use on
first run and after each update before it will open.

Unauthorized interception or decryption of radio communications is illegal in
most jurisdictions — for example the U.S. Wiretap Act (18 U.S.C. §§ 2510-2522)
and § 2512, Spain's Codigo Penal art. 197, and the U.K. Investigatory Powers Act.
All responsibility for use rests with the user; see the "Legal & responsible use"
section of [README.md](README.md) and [LICENSE](LICENSE).

## Reporting a vulnerability

This policy covers vulnerabilities **in the tool itself** (crashes, memory-safety
bugs, unsafe file or process handling, supply-chain concerns in the bundled
DSD-FME runtime, the updater, or the build). It is not a channel for help cracking
a signal.

Please report privately, not in public issues: open a **private security
advisory** via GitHub (`Security` tab -> `Report a vulnerability`).

Include:

- A clear description and the impact you observed.
- Steps to reproduce (input file, command line or GUI actions).
- Version (`dmrcrack --version` or the GUI title bar) and platform
  (OS, GPU, back-end: CUDA / HIP / OpenCL / CPU).
- Any crash log, stack trace, or `.dslog.txt` / `.progress` artifacts.

## What to expect

- Acknowledgement within a few days.
- A fix or mitigation plan for confirmed issues, with credit in the changelog
  if you want it.
- Coordinated disclosure: please give us reasonable time to ship a fix before
  going public.

## Out of scope

- Requests to recover keys, decrypt captures, or target third-party systems.
- The intended capability of the tool (recovering 40-bit RC4 keys) is not a
  vulnerability.
- Misuse of the tool by third parties. Responsibility for use rests with the
  user; see the legal notice in the [README](README.md).

## Supported versions

Security fixes target the **latest release**. Older versions are not patched;
please update before reporting.
