# DNP3-EXTRA execution phase ledger

**Baseline:** `develop@9b2534b37152f07a439f892ba8d27c3a9863653f` (2026-11-08).  
**Scope:** only the supplied execution phases A-E. **Windows builds and tests were not run.**  
**Acceptance:** no implementation or compliance status is upgraded to VERIFIED without matching runtime evidence.

| Phase | Requirement IDs | Result in this handoff | Commit or artifact | Outstanding gate |
|---|---|---|---|---|
| A: G120V8 | PROFILE-055 | BLOCKED_INPUT; no runtime certificate acceptance was added | This ledger | Approved IEEE certificate profile, types/encoding, authority, trust, association/user binding and independent oracle |
| B: security policy | SEC-T1-09, SEC-T1-11, SEC-T1-03, SEC-T1-13, SEC-T1-15, SEC-T1-16; CFG-02/03/07/09/10/12 | BLOCKED_INPUT; policy values are not guessed | This ledger | Explicit owner choices for MAC, RUK/certificates, TLS1.3 suites, timers, revocation interval and other blank device-profile fields |
| C: authenticated FC6 coverage | PROFILE-019, PROFILE-035..037, CFG-08 | TEST_TITLES_ONLY; existing runtime remains unchanged | `WINDOWS_TEST_TITLES.md` | Implement/execute targeted Method 4/68, Challenge/Aggressive, TCP receiver execution, denial/replay/timeout cases |
| D: optional TLS CRL check | SEC-T1-15 (partial) | IMPLEMENTED_UNVERIFIED; optional TLS context issuer CRL checking added, no Windows execution | `232a1e15d18de6985df1d4c5260d2bf23a7bb79a` | Windows build/handshake tests; product-defined revocation polling interval, CRL reload and treatment of established connections |
| E: FC22 qualifier cases | PROFILE-010, PROFILE-020, PROFILE-045 | TEST_TITLES_ONLY; code and tests unchanged | `WINDOWS_TEST_TITLES.md` | Implement/execute six Q00/Q01/Q06 unit cases, then full Windows regression |

## Unresolved source decisions

- `P4-OPEN-01`: retain provisional G120V7 Code 5 = MAC Algorithm Not Supported and Code 7 = Authorization Failed. No IEEE erratum is claimed.
- `PROFILE-001` G0V209 remains unadvertised until applicable SA v5 capabilities and independent interoperability are demonstrated.
- `SEC-T1-15`: supplying `--crl` enables context-initialization CRL verification only; no scheduled reload or live-connection revocation check has been implemented.
- TLS 1.3 cipher names shown in the supplied security addendum require a product decision; do not silently substitute TLS 1.2 cipher names.
- Host implementation and independent peer interoperability, STM32H743/FreeRTOS integration and hardware acceptance are distinct verification stages.

## Deferred unified Windows evidence

All planned cases are titles only in `WINDOWS_TEST_TITLES.md`. The future test campaign must record revision SHA, exact commands, per-suite exit codes and logs, receiver-side effects and remaining failures. A green self-interoperability result must not be presented as third-party certification.

No Git history was rewritten. Other unapproved source areas are unchanged.

## Implementation-only follow-up

The user deferred authoring and running automated acceptance tests until the
implementation campaign is complete. The following changes require later evidence:

| Scope | Implemented scope | Pending |
|---|---|---|
| Group 70 | V2–V8 wire codecs and Q5B dispatch; opt-in REQUIRED-mode Outstation GET_FILE_INFO provider | Master task/API, file transfer session and storage, open/read/write/close/delete/abort, credentials, timeout events, activation policy and independent peer |
| G70V1 | Superseded by modern file control in IEEE 1815-2012 A.27.1 | Legacy interoperability is a separate product requirement if requested |
| FC22 | Preserve active class across consecutive data headers and report dangling class sets | Full qualifier/association/process acceptance |
| G122 | Timestamp before Save; apply the Save result to the same event's discontinuity flag | Permanent retention, real restart and event/CONFIRM acceptance |
| CFG-03 | Diagnostic RX/TX fragment configuration in both roles | Product bounds, wire and resource evidence |
| G120V8 | Validate certificate type and method fields on the wire | IEC/TS 62351-8 validation and trusted runtime lifecycle |
