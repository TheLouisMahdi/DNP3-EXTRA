# DNP3-EXTRA - Windows Host remaining work and acceptance

**Prepared:** 2026-11-10  
**Source baseline:** live `develop@99e1c4ca3d9eacc179ae16e24f1e7dc68fc09b33` before this implementation slice.  
**Contractual inventory:** 69 PROFILE, 14 CFG, 36 SEC IDs = 119 IDs; use only applicable selections in the 12-page Tavanir Device Profile excerpt (original pages 41-52), 6-page security addendum, and corresponding IEEE 1815-2012 behavior.

This is the **single active Windows Host roadmap**. Earlier phase plans are historical, not future obligations. Work is limited to independent Windows Master and Outstation processes communicating over real TCP/TLS. Hardware and firmware delivery are excluded. Every row requires matching passing evidence at a recorded source revision; historical counts are not current verification.

## Already implemented - verify rather than rewrite

Existing code includes native Master/Outstation, real TCP, measurement/event encoding, class polling, controls, time operations, link confirmations/retries, fragmentation, SA v5 Challenge/Reply, Aggressive Mode, Methods 4/68, Windows credential adapters, TLS, G0V210, G121/G122 and process fixtures. These capabilities have different evidence levels and MUST NOT be reported as all verified. Preserve existing architecture, tests and authorization boundaries.

## Implemented in the 2026-11-10 slice - Windows validation pending

- `PROFILE-030`: the `--rtu-io-profile` Outstation defaults analog events to selected G32V5 (float32, without time); generic diagnostics keep G32V7. The permanent `pc-profile-analog` process test checks both. **IMPLEMENTED_UNVERIFIED**, not a Windows PASS.
- `PROFILE-035..037`: the RTU diagnostic Outstation accepts selected G41V1/V2/V3 and now rejects unselected G41V4 on SELECT and operate paths. The generic diagnostic handler retains G41V4. Added positive G41V3 and negative G41V4 FC3/FC5/FC6 receiver-side checks to `pc-profile-analog`. **IMPLEMENTED_UNVERIFIED**.
- `CFG-09` / `PROFILE-019`: the actual PDF selects **Pulse On = Sometimes**, **Pulse Off = Never**, **Trip/Close = Always**, **Count >1 = Never** and rejects Latch/Queue. Corrected live matrices and audit notes. The Host policy is **OWNER_APPROVED / IMPLEMENTATION_PENDING**: 0x41/0x81 on Complementary points, 0x01 on explicitly enabled Activation points only. Actual target point mapping and pulse/interlock parameters remain open; existing CLI is partial.

## Actual remaining gaps and acceptance work

| Area | IDs | Work needed |
| --- | --- | --- |
| Windows secure profile and controls | CFG-08/09, PROFILE-019/035-037, SEC-T2-09/10/11 | Provide fail-closed configuration and provisioning; exercise selected G12/G41 FC3/4/5/6 with authentication and receiver-side effects. FC6 has no application response. |
| Restart, unsolicited and IIN | PROFILE-068, CFG-11/12 | A meaningful simulated COLD_RESTART remains missing; validate startup, restart indication, events, confirmation and reconnection. An unsolicited NULL with no static values is not proof of CFG-12. |
| SA certificates and attributes | PROFILE-001/055, SEC-T1-01/16/17 | G120V8 user certificate runtime, binding and trust are incomplete; expose G0V209 only once truthful SA v5 capability is verified. Preserve G0V210. |
| Security life cycle | SEC-T1-03/07/08/09/11/13/14/15/16, applicable SEC-T2/T3 | Verify approved MAC and RUK modes, renewals, roles, password/secret protection, TLS mutual trust, 4 CAs, CRL reevaluation/revocation and cipher-change timing. Test-only provisioning is not production enrollment. |
| Remaining selected wire cases | All other applicable PROFILE/CFG | Verify FC, request/response qualifiers, V0 defaults, timestamps, class/unsolicited flows, fragmentation, retry exhaustion, timeouts and malformed/unauthorized/replayed input. Fix only confirmed defects; do not add unselected IEEE Level 4 objects. |

## Contractual decisions

- **CFG-09:** Host Pulse On policy approved; implement per-point behavior and tests. Obtain actual target mapping, durations and interlocks separately.
- **CFG-12:** normative startup NULL versus selected unsolicited static data on restart.
- **SEC-T1-09/11/16:** MAC allowlist, conflicting TLS 1.2/1.3 table/cipher names, RUK methods and authority.
- **SEC-T1-03/13/15:** timeout zero, cipher-change/KeyUpdate meaning, revocation source and cadence. Use IEEE normative limits; do not invent approvals.
- **PROFILE-055 / SEC-T2-10:** G120V8 external certificate profile and authorization roles.
- Preserve **P4-OPEN-01** unresolved: provisional G120V7 code 5 = MAC Algorithm Not Supported; code 7 = Authorization Failed. No official IEEE erratum is claimed.

## Verification and release gates

1. Record new live HEAD and working-tree state. Recheck any uncommitted Google Drive or local copy against remote; never discard WIP.
2. Build only current Windows targets, then run focused `pc-profile-analog`, Link, controls and SA tests. Exercise actual separate-process TCP and mutual TLS (positive and negative cases).
3. Close selected protocol and security gaps with smallest code changes plus permanent positive, negative, malformed, boundary, timeout, ownership, replay and independent wire assertions.
4. Reconcile 69 PROFILE, 14 CFG and 36 SEC IDs, including all applicable selected subcases, with **tested SHA, commands, expected/observed behavior, logs and test result**. Record recommended versus mandatory rows separately.
5. Run final Host regression; promote a requirement to VERIFIED only when all its selected applicable subcases have sufficient passing evidence. Report blocked decisions and independent-peer limitations explicitly.

**Focused validation on the user's Windows checkout** (first verify CMake target names and the existing `build/native` directory):

```powershell
$ErrorActionPreference = 'Stop'
if (!(Test-Path './AGENTS.md')) { throw 'Start from the DNP3-EXTRA repository root.' }
if ((git branch --show-current) -ne 'develop') { throw 'Expected develop branch.' }
git status --short
git rev-parse HEAD
cmake --build build/native --config Release --target dnp3-cli --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
ctest --test-dir build/native -C Release -R '^pc-profile-analog$' --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'G32V5 process test failed.' }
```

These are instructions, **not reported executions**. No complete Windows Host conformance or 100% compliance is claimed while mandatory subcases are unverified or contractually blocked.

## G120V8 IEC source gate clarified (2026-11-10)

- IEC/TS 62351-8:2011 is now available; the text-source blocker is closed. Normative details: `G120V8_IEC62351_2011_PROFILE.md`. Post-implementation checks: `G120V8_DUE_AFTER_IMPLEMENTATION.md`.
- **Pre-implementation**: RFC5280/5755 and applicable IEC/TS 62351-3 review; security policy, laboratory CA/AA, DNP3 RoleID/AoR binding and receive-fragment support for an 8192-byte IEC token plus protocol overhead. A 4096-byte Host fragment limit alone does not cover this.
- **Current static status:** Group120Var8 codec exists, RemoteUpdateKeys native G120V8 acceptance/verification absent. `PROFILE-055=MISSING_RUNTIME`, not verified. All applicable unit/wire/TCP tests and true external peer are still due; no build/test was run in this documentation audit.
