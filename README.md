# DNP3-EXTRA

DNP3 Master and Outstation development on OpenDNP3, with a Windows console for protocol diagnostics, Secure Authentication v5 and mutual TLS.

## Standards implementation progress

Implementation progress is not equivalent to IEEE certification or independent interoperability conformance.

<!-- progress:start -->

![IEEE 1815-2012. Audit in progress.](DNP3_PDD_PLAN/progress-ieee.svg)

![RTU Device Profile. Verified 17.39% (12/69), implementation coverage 84.06% (58/69).](DNP3_PDD_PLAN/progress-profile.svg)

![RTU Security Requirements. Verified 42.42% (14/33), implementation coverage 48.48% (16/33).](DNP3_PDD_PLAN/progress-security.svg)

| Scope | Verified | Implemented, unverified | Partial | Missing | Not audited | Not applicable | Blocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| IEEE 1815-2012 / Outstation | 0 | 4 | 6 | 0 | 1 | 0 | 0 |
| IEEE 1815-2012 / Master | 0 | 4 | 6 | 0 | 1 | 0 | 0 |
| RTU Device Profile / Outstation | 12 | 46 | 9 | 2 | 0 | 0 | 0 |
| RTU Device Profile / Master | 12 | 46 | 10 | 1 | 0 | 0 | 0 |
| RTU Security Requirements / Outstation | 14 | 2 | 11 | 3 | 5 | 0 | 1 |
| RTU Security Requirements / Master | 14 | 2 | 9 | 2 | 0 | 8 | 1 |

| Role and scope | Strict verified | Implementation coverage | Open issue IDs |
| --- | --- | --- | ---: |
| IEEE 1815-2012 / Outstation | AUDIT IN PROGRESS | AUDIT IN PROGRESS | 13 |
| IEEE 1815-2012 / Master | AUDIT IN PROGRESS | AUDIT IN PROGRESS | 13 |
| RTU Device Profile / Outstation | 17.39% (12/69) | 84.06% (58/69) | 14 |
| RTU Device Profile / Master | 17.39% (12/69) | 84.06% (58/69) | 14 |
| RTU Security Requirements / Outstation | 42.42% (14/33) | 48.48% (16/33) | 21 |
| RTU Security Requirements / Master (8 not applicable) | 51.85% (14/27) | 59.26% (16/27) | 21 |
| Profile G120 / Outstation | 60.00% (9/15) | 60.00% (9/15) | 5 |
| Profile G120 / Master | 60.00% (9/15) | 60.00% (9/15) | 5 |
| Security recommended rows | 2 not audited | Excluded from mandatory metrics | — |
| Security optional rows | 0 rows | Excluded from mandatory metrics | — |
| Security unresolved rows | 1 partial | Excluded from mandatory metrics | — |

Bar order: verified (green), implemented without verification (cyan), partial (amber), missing (red), not audited (slate), blocked (violet).

Latest tracked source commit **4d9f7bbaea1fcf305d942abe7891384df18a6199**. Audit revision **4d9f7bbaea1fcf305d942abe7891384df18a6199**.
Last tested revision **4d9f7bbaea1fcf305d942abe7891384df18a6199** on 2026-11-03 (Windows x64 Release).
Unit **714 cases / 59,048 assertions**. Integration **12 cases / 241 assertions**, including SA TCP. [Execution evidence](cli/README.md)
Historical SA TCP baseline **2 cases / 240 assertions** at `33d7994ae551e4f3b30b7ddfb894e59c6b9e336d`.

Windows execution evidence applies to the tracked source revision.

Outstation items awaiting audit:
- **IEEE 1815-2012** — `IEEE-LEVEL4-ENUMERATION`
- **RTU Device Profile** — None within the listed rows
- **RTU Security Requirements** — `SEC-T3-01`, `SEC-T3-02`, `SEC-T3-06`, `SEC-T3-07`, `SEC-T3-08`

[Formulas, evidence scope and open decisions](DNP3_PDD_PLAN/PROGRESS.md)

<!-- progress:end -->

## Requirements coverage

The Device Profile covers the 69 object and function rows identified in a 12-page excerpt from a 78-page document. The excerpt identifies a Level 3 Outstation. The separate Level 4 and SA v5 audit follows IEEE 1815-2012. The security requirements cover three tables in a six-page amendment. [Source index](DNP3_PDD_PLAN/01_SOURCE_MAP.md)

The source matrices keep Outstation and Master assessments separate. The Outstation assessment determines the primary profile count. For security, each row assesses the named RTU obligation using Windows evidence where applicable. [Device Profile](DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv) · [Security requirements](DNP3_PDD_PLAN/03_SECURITY_MATRIX.md) · [Security audit](DNP3_PDD_PLAN/SECURITY_PROGRESS.csv) · [IEEE traceability](DNP3_PDD_PLAN/IEEE_TRACEABILITY.csv)

## Windows Master and Outstation

Run `dnp3-cli.exe outstation` and `dnp3-cli.exe master` in separate terminals. The default compatibility connection uses `127.0.0.1:20000`. The guide covers the Release build, measurement scans, simulated controls, SA provisioning, TLS on port 19999 and repeatable process tests. [Build and run](cli/README.md)

The Windows environment exercises SA session keys, Challenge/Reply, Aggressive Mode, remote Update Key Methods 4 and 68, user lifecycle and G121/G122. Remote authority provisioning in the console uses test credentials. [Remote Update Keys](DNP3_PDD_PLAN/SA_REMOTE_UPDATE_KEYS_REPORT.md) · [Windows acceptance evidence](cli/README.md#windows-acceptance-evidence)

## Engineering evidence

G0V209 advertisement, runtime G120V8, independent interoperability, RTU hardening and outstanding security profile decisions remain open. [Audit notes and regeneration](DNP3_PDD_PLAN/PROGRESS.md) · [Repository map](REPO_MAP.md)
