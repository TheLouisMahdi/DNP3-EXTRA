# DNP3 119-requirement reference audit

**Disposition** — operational Windows Host reference with scoped normative verification and explicit external and implementation evidence gates.

## Source revisions

- Initial live `develop` and code inspected — `c25dd10d2de22467a841d5d9d2416701cce85a8e`.
- Final observed `origin/develop` — `962fe03652cac7255dad9ae21e9510e9461feb0b`. The intervening commit changes only `EXECUTION_PHASE_STATUS.md`.
- The supplied ZIP had local HEAD `da2c31bd5d725fa699f4f3f55c1dee9a61f6c6b9` and unrelated working changes. Those changes were preserved.
- Historical `PDF_SCOPE.md`, `PROFILE_MATRIX.csv`, `SECURITY_MATRIX.csv` and `OPEN_ISSUES.md` came from pinned Git history. The candidate CSVs and candidate audit/usage Markdown were absent. Their operational outputs were regenerated from the delivered workbook.

## Integrity and scope

- 119 unique IDs, matching the input workbook and current project coverage register. 69 Profile, 14 CFG and 36 Security.
- All 71 backlog rows received independent source review. 67 are marked `NORMATIVE_VERIFIED` for the reviewed subcases and 4 retain explicit exceptions.
- All 30 decisions have recorded dispositions. 19 engineering baselines, 7 external-class decision entries, two implementation-evidence entries, one explicit contract entry and one outside Windows Host.
- 36 distinct wire/policy procedures. 15 original worksheet names and original source rows retained. The exact selected FC/Q column and procedures supersede compact summaries.
- No runtime was executed for this review. The final remote ledger records 14 distinct Windows CTest passes at the inspected code SHA. The workbook links scoped witnesses where relevant. Independent peer and full requirement acceptance remain pending.

## Remaining source exceptions and release gates

- **PROFILE-060** — Core V13 pairings and FCs verified; Method 68 companion signature encoding still provisional under D-24.
- **PROFILE-062** — Core V15 confirmation wire verified; Method 68 companion signature encoding remains under D-24.
- **PROFILE-065** — Event encoding is verified. P6-OPEN-01 threshold wording differs between §7.6.1.4.2 and §11.9.10.2; use the D-25 baseline.
- **PROFILE-066** — Event encoding is verified. P6-OPEN-01 threshold wording differs between §7.6.1.4.2 and §11.9.10.2; use the D-25 baseline.
- IEEE Table 12-63 at physical p416 corroborates G122V0 FC1 Q00/01/06/17/28. Separately, §11.9.10 requires durable statistics totals and prohibits freeze/clear; the actual Windows durable store still needs evidence.
- Retain the distinction between the conditional IEEE authenticated FC0 dependency and the profile's displayed FC1–31 Aggressive range. Verify the separate V1 trailer and V3/V9 confirmation exchange at the wire level.
- The other 48 requirement records were reconciled against the active decision and procedure indexes. The count of independently verified backlog rows covers the 71 requested detailed reviews.
- Review unresolved TLS-era support for the IEEE mandatory TLS1.2 suite and configurable cipher-change timeout alongside the selected profile. Confirm production revocation, roles and identity only against their own evidence.
- The workbook preserves G120V7 Code 5/7 provisionally. No authoritative erratum was obtained.

## External authority decision entries

- **D-01** — Product owner must supply identity.
- **D-10** — Project owner (2026-11-10) selected IEEE-strict startup/unsolicited implementation. Tavanir must separately reconcile its selected static-unsolicited-on-restart acceptance subcase. No nonstandard compatibility mode is authorized.
- **D-13** — Tavanir must reconcile TLS version and suite table; no claim of full IEEE TLS conformance.
- **D-15** — Deployment acceptance requires provisioned CA chains and peer identities.
- **D-18** — Project owner (2026-11-10) selected full IEEE-strict G120V8 Host implementation and permanent test harness. The applicable IEC/TS 62351-8 certificate profile, external authoritative fixtures, and production trust/AoR provisioning remain required.
- **D-23** — Authoritative clarification or agreed independent-peer profile required.
- **D-24** — SCS rollover reconciliation and Method 68 signature wire encoding evidence outstanding.
- D-11's 0→2 s alias and D-12's TCP MAC baseline can guide implementation. Contractual meaning of zero and any additional mandatory MAC choices remain unconfirmed.

## Explicit owner decisions after the Work baseline

- **CFG-12 / D-10**: IEEE 1815-2012 §4.6.6 and §5.1.1.1 control startup. Initial unsolicited NULL is object-free, and §7.5.2.3.2(h) expressly prohibits G120V1 in the initial NULL. Master confirms promptly, performs the prescribed IIN1.7/SA/clear/integrity/FC20 sequence, and parses static unsolicited data if received from another peer. Outstation does not originate prohibited static data. This is an implementation policy decision, **not** Tavanir contractual acceptance.
- **PROFILE-055 / D-18**: IEEE Annex A.45.8 requires FC32/Q5B singleton and external-authority-signed ID/Attribute certificates used only with asymmetric Update Key methods. Full certificate validation, state transitions, negative tests and separate-process TCP test harness are implementation targets. The referenced external certificate specifications must be consulted, with real deployment CA/AoR provisioned explicitly; test certificates cannot prove production PKI acceptance.
- Both rows remain **implementation and runtime evidence pending**. No production code or tests were changed or executed for these corrections. The decision register's external-gate count still includes D-10 and D-18 because external contractual acceptance and certificate provisioning remain outstanding, although the IEEE implementation policy has been decided.

## Verification and publication

- Verified source PDF digests, selected source-page mapping, clause references for the reviewed paths, ID sets, decision IDs, procedure cross-references, worksheet round-trip, formula results and cell-for-cell CSV exports. The workbook uses plain clause/page references and has no Excel hyperlinks to resolve.
- `git diff --check` passed for the isolated worktree and the intervening upstream documentation commit. This review changes reference artifacts and navigation only. Production code and tests are outside this revision.
- The corrected package contains the editable XLSX, two cell-matched derived CSV files, this audit, the owner-updated decisions register and the usage guide. Repository navigation points to the operational CSV first.
