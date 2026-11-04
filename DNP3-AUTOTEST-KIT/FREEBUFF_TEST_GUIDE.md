# DNP3-EXTRA: deterministic Windows acceptance-test task for Freebuff

## Mission and hard boundary

Implement and execute an **automated, evidence-producing** Windows test campaign for the **actual** DNP3-EXTRA Master and Outstation, then compare observed protocol behavior against the selected Device Profile, RTU security requirements and existing test oracles. The user explicitly authorizes building and executing local tests for this task, overriding the general P10 no-test restriction in AGENTS.md **for this test task only**. Do not claim IEEE Level 4, SA v5, product RTU or third-party interoperability certification on the basis of self-interoperability.

This is a **QA-only** task. Do **not** edit production code, `AGENTS.md`, existing requirements/matrix assessments, dashboards or Git history; do not commit or push. If production code appears defective, capture a minimal reproduction and mark FAIL or BLOCKED rather than quietly fixing it. You may change `cli/tests/ProcessSmoke.py` minimally and add small, focused QA files if necessary. Preserve unrelated working-tree changes, especially `AGENTS.md`. Do not install or upgrade Python, CMake, OpenSSL, MSVC, vcpkg, Node, system packages or project dependencies. Use only the verified Windows installation and already-configured CMake build. No tests against a deployed device or non-loopback host.

## Source of truth and start-up (read in order)

1. Read `AGENTS.md` and `REPO_MAP.md`. Confirm the Git root, branch, HEAD, staged/unstaged/untracked status; preserve any user edits. Expected published starting revision when this guide was authored: `aa15ccba701740dd76a2a43f6ff0f58847271983`, branch `develop`. If HEAD differs, record the actual revision and adapt; never reset or overwrite.
2. Read `cli/README.md`, `cli/tests/ProcessSmoke.py`, `cli/CMakeLists.txt`, and `opendnp3/cpp/tests/{unit,asiotests,integration}/CMakeLists.txt`. `ProcessSmoke.py` **already implements** `Peer`, `connected`, process cleanup and scenarios: compat, method4, method68, negative, TLS. Reuse these. Do not create a competing terminal-driving framework.
3. Read `DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv` (69 selected Profile rows), `03_SECURITY_MATRIX.md` (36 SEC IDs, not all mandatory), `SECURITY_PROGRESS.csv`, `IEEE_TRACEABILITY.csv`, `ISSUE_POSPONED1.md`, `PROGRESS.md`, and `04_G0V209_CONTRACT.md`. Refer to the IEEE 1815-2012 original only if present and legitimately accessible locally. Do not download, upload or copy proprietary standard PDFs to a cloud service. Source matrices are navigation aids; not proof of conformance.
4. Read `TEST_CASES.json`. Treat its `requirements_manifest` as the COMPLETE coverage accounting list, but not an assertion that any listed requirement is implemented or tested. Do not mark an item PASS just because a test with a similar name passes.

## Execution environment (detect, don't guess)

- Repo: use `git rev-parse --show-toplevel` to locate the workspace.
- Existing build: use the configured Windows Release build for this workspace.
- CMake: resolve the installed `cmake.exe` and `ctest.exe` with `Get-Command`.
- CLI binary: `<build>\cli\Release\dnp3-cli.exe` after a successful Release build.
- Python: use the Python interpreter already registered in the CMake cache or actually installed on the host. Do not assume a `python` alias or attempt trial versions/installations.
- First run the existing Release build (`--target dnp3-cli unittests integrationtests asiotests --parallel 4`) and one full CTest (`-C Release -j 1 --output-on-failure`). The expected CTest names are `unittests`, `asiotests`, `integrationtests`, `pc-compat`, `pc-method4`, `pc-method68`, `pc-negative`, `pc-tls`. Check `ctest -N` first. Missing suites are BLOCKED, not PASS.
- Then execute **all available** CTest suites in parallel (`-j 4`) at least once. If all pass, optionally repeat for flakiness, subject to a bounded overall budget. Never silently skip a failed suite or treat a retry as erasing the earlier failure.
- Existing CLI automation already launches *both processes* through `subprocess.Popen` and feeds stdin pipes, so there is no need for manual terminals, UI automation, or GUI interaction. Prefer `ProcessSmoke.Peer` plus `connected` for new tests. The existing `ctest` process tests cover real TCP/TLS, not mocked success strings.

## New QA scenarios, in priority order

Implement missing cases from `TEST_CASES.json` against the existing harness, **one small self-contained group at a time**. Begin with COMPAT static/events/output readback, ASSIGN_CLASS, then UNSOL/CONFIRM; continue with SA, TLS, negatives and gaps. Reuse production CLI syntax exactly as defined in `cli/main.cpp` / `cli/README.md`. Do not invent unsupported commands.

**Representative protocol assertions that must be checked:**

- When setting Analog[0] to 13.75, `read 30 5 0 0` and `read 32 7` must yield 13.75; a separate `read 32 4` after setting 12.5 can demonstrate the expected 16-bit integer variation, but never substitute it for float fidelity.
- After `crob 0 on` and `analog 3 0 1.5`, verify *both* completion SUCCESS and native readback (`G10V2 ON`, `G40V3 1.5`), and verify actual Outstation simulated execution counts. A command submission alone is not evidence.
- `assign 30 3 0 0` followed by `set analog 0 14.25 force`, then `scan class3`, must deliver G32V7 Analog[0]=14.25. Avoid unrelated pending events by using fresh peers per case.
- For Unsolicited: launch Outstation with `--unsolicited`; `unsol on`; generate a **new** `set binary 3 on force`; verify `UNSOLICITED_RESPONSE` with G2V2 and `CON=1`; match the exact *application* sequence number (`SEQ`) of the Master `CONFIRM` and Outstation's received `CONFIRM` from captured traces. Confirming only Master TX is an incomplete pass. To assert event removal, create a separate scenario that checks no replay after confirmation; beware that `force` can create a second, legitimate event even with the same value.
- For `unsol off`: require command TASK SUCCESS, then generate a **new** binary event; assert *absence* of the unsolicited G2V2 for a bounded interval while both peers stay OPEN; finally poll Class 1 and verify the correct event appears once. Absence assertions need a monotonic-clock bounded wait and cannot pass because the process exited.
- Confirm `attr 209` is *not* advertised in the incomplete Outstation SA v5 implementation. Expected `OBJECT_UNKNOWN`/request-error evidence is PASS **for the truthful-negative contract only**, NOT a pass for the Profile's G0V209 support obligation. `attr 210` in compat yields 0 and with a valid SA association yields the actual nonzero count; verify discovery V254/V255 accordingly.
- SA: cover Method 4 and 68, challenge/reply, Aggressive mode, change/verify/add/delete user, authorized and denied controls, replay/timeouts and per-association G121/G122 where supported. Do not interpret `auth=compat` as testing SA. Use unique disposable `--test-only --profile` names and `--trust-system-time` where required; do not print or persist secrets.
- TLS: reuse `pc-tls`; cover 1.2/1.3, mutual certificates, issuer/trust, SAN mismatch, expired/untrusted certificates, four independent CA anchors and secured control behavior. Real credential-revocation scheduling is **not** implemented by the existing CLI and cannot be marked PASS by a handshake test.

## Deterministic test engineering requirements

1. Orchestration: use standard-library Python 3 and existing CTest; no `pexpect`, `pytest`, PowerShell SendKeys, interactive keystroke simulation, shell-quoted stdin tricks or new dependencies.
2. Each test has a unique name, clean process pair, distinct ephemeral localhost port for new sessions, state setup, explicit command sequence, bounded deadlines (connection 20 s, task 30 s, CLI cleanup 15 s; justify longer cases), and `try/finally` resource cleanup. Use `Peer.connected()` / `Peer.task()` patterns already in the repo. Never use a fixed 20000 port for the new cases.
3. Synchronize on `LINK OPEN`, per-command `TASK ... SUCCESS` or an expected failure, and *matching* event values/timestamps/sequence. Do not use arbitrary sleeps as a substitute for expected events. A short bounded interval is appropriate *only* to prove absence, e.g. UNSOL OFF; check process liveness during it.
4. Observe both peers' logs. A PASS requires specific output **and** no contradictory failure, wrong IIN, silent timeout, process crash, stale output from an earlier case, or unacknowledged control. Only accept expected IIN errors as passing where the test explicitly requires rejection.
5. Negative tests must prove no forbidden handler invocation: capture Outstation `executed=` before/after where available. A failed Master task alone is insufficient for an authorization test.
6. Do not expose crypto payloads, keys, private PEMs, profile secret material or user credentials in reports. Existing SA trace is deliberately metadata-only. Remove only test-created local profiles/cert directories after peers stop; preserve pre-existing credentials and data.
7. Keep complete raw stdout/stderr per process (redacted if sensitive) and command chronology. Every test result includes the exact observed evidence, required oracle, elapsed time, CTest/CLI exit codes, branch, HEAD, build config and OS. Avoid PASS based on mere regex occurrence across an entire multi-case log; scope matching to current test cursor.
8. Never modify the production implementation to make a test pass. If blocked by a missing feature or CLI gap, classify it explicitly (`NOT_IMPLEMENTED`, `BLOCKED_EXTERNAL`, `BLOCKED_HARDWARE`, `BLOCKED_SPEC`, or `NOT_AUTOMATABLE_WITH_CLI`) and provide the smallest proposed future test hook, without silently installing a substitute feature.
9. If a regression is observed, preserve it as FAIL, record a deterministic reproduction, stop expanding that path, and continue only independent tests. Don't weaken assertions or rewrite expectations to get green.
10. **No Git commit/push**, no change to dashboard percentages, no modification to `AGENTS.md`. Before ending, show a complete `git diff --stat` and `git status --short` and identify QA-only changes. Existing user's local changes must remain intact.

## Result classification and traceability

Result vocabulary: `PASS`, `FAIL`, `NOT_RUN`, `NOT_IMPLEMENTED`, `BLOCKED_EXTERNAL`, `BLOCKED_HARDWARE`, `BLOCKED_SPEC`, `NOT_AUTOMATABLE_WITH_CLI`, `NOT_APPLICABLE` (requires explicit justification). Existing historical matrix `VERIFIED` status is not fresh verification. `BLOCKED` is not PASS.

Deliver under `<build>/qa-results/<run-id>/` (outside source tree, unless a checked-in ignored evidence directory already exists):

- `report.json`: machine-readable top-level branch, exact HEAD, UTC time, platform, build/CTest commands and exit codes, and one object per test with ID, status, oracle, observed values, evidence file paths, reason and elapsed milliseconds.
- `report.md`: human-readable Persian or English summary with totals and a failure-first table; list new source QA files and exact commands to reproduce any failure.
- `logs/`: independent Master, Outstation, CTest and build logs for each case; redact sensitive data; never store private keys.
- `coverage.json`: **every one of the 69** PROFILE IDs and **all 36** security IDs mapped to one or more test IDs/evidence or an explicit gap. Distinguish Outstation vs Master and whether a test is self-interoperability, source review, external peer or hardware. Include mandatory/optional/conditional classification and justification from source documents. Do not inflate verified counts by treating an entire family as verified after one positive sample.

Example JSON case entry:

```json
{
  "id": "UNSOL-CONFIRM-01",
  "status": "PASS",
  "expected": ["RX UNSOLICITED_RESPONSE CON=1", "MASTER TX CONFIRM matching SEQ", "OUTSTATION RX CONFIRM matching SEQ"],
  "observed": {"unsolicited_seq": 4, "master_confirm_seq": 4, "outstation_confirm_seq": 4},
  "master_log": "logs/UNSOL-CONFIRM-01.master.log",
  "outstation_log": "logs/UNSOL-CONFIRM-01.outstation.log"
}
```

**Stopping rule:** stop when each applicable obligation is either supported by specific recorded evidence **or** explicitly classified as a documented gap. "Every case accounted for" does NOT mean "every standard requirement has passed". Provide an honest capability gap list requiring new code, independent DNP3 Test Harness, production provisioning decisions or STM32/RTU hardware.

## Low-token workflow for a cheaper agent

- First response: a short inventory (real build directory and active CTest suites), no repo-wide dump.
- Read only the files listed above, not all 1,700+ files; use `rg` only for target symbols.
- Stage A: run existing 8 CTest suites and create evidence, without editing source.
- Stage B: add the few missing `ProcessSmoke.py` scenarios, run each narrowly, then a single full regression.
- Stage C: make the 105-row coverage report; do not attempt to implement missing product requirements in this assignment.
- Provide final summary containing pass/fail/blocked and exact SHA. If something cannot be tested automatically, state why rather than guessing.
