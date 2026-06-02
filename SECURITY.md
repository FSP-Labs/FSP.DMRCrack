# Security Policy

FSP.DMRCrack is a security-auditing and research tool. This policy covers
vulnerabilities **in the tool itself** (crashes, memory-safety bugs, unsafe
file or process handling, supply-chain concerns in the bundled DSD-FME runtime,
the updater, or the build). It is not a channel for help cracking a signal.

## Reporting a vulnerability

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
