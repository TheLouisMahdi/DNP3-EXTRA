# FC6-B3 evidence and traceability audit

## Scope and assessment

This audit covers IEEE 1815-2012 §4.4.5 no-application-response behavior and
the selected command obligations in Table 14-5: `IEEE-CONTROLS`,
`L4-BINARY-CONTROL`, `L4-ANALOG-CONTROL`, the eight G12V1/G41V1-3 FC6 wire
rows, and Device Profile rows `PROFILE-019` and `PROFILE-035` through
`PROFILE-037`.

The eight detailed FC6 rows now record `VERIFIED_SUBSET` for Master and
Outstation, with aggregate outcome `PARTIAL`. The subset is the tested typed
FC6 request and no-response path in Compatibility mode, not full control or
product conformance. The broader IEEE control rows remain partial or
implemented-but-unverified. The Profile rows likewise retain their existing
partial or implemented-but-unverified assessment; FC6 coverage does not
complete their FC3/FC4/FC5 requirements or the whole profile row. `PROFILE-019`
now has `local_code_status=PARTIAL`, matching its Outstation status. No coverage
percentage is increased by this audit.

## Evidence by role

**Master transmission and completion.** The command task selects FC6 and uses
the shared typed command writer. The focused `[fc6-master]` tests cover CROB
and G41V1/V2/V3 payloads with 8-bit and 16-bit index qualifiers, exactly one
FC6 application request, local completion only after `OnTxReady()`, and
`CommandStatus::UNDEFINED` rather than a remote success status. Seventeen
sequential requests establish application sequence progression modulo 16.
The subsequent ordinary SELECT/OPERATE request verifies sequence continuity
and unchanged normal command behavior.
Advancing the mock timer after each locally completed request confirms no
application retry. Separate focused cases cover transmit timeout, disconnect
before transmit completion, and rejection when authentication is REQUIRED.
The permanent unit coverage is in
[TestProfileControls.cpp](../opendnp3/cpp/tests/unit/TestProfileControls.cpp);
the process scenarios are in
[ProcessSmoke.py](../cli/tests/ProcessSmoke.py).

**Outstation parsing and execution.** Unit fixture assertions exercise FC6
parsing and the CROB/analog command handlers for both index qualifier widths.
The `pc-compat` real TCP process scenario uses the project's own Master and
Outstation: it observes one simulated execution and subsequent output readback
for CROB and G41V1 through G41V4. The G41V4 process check is outside the eight
detailed G41V1-3 wire rows. It also sends a valid FC6 command to unsupported
output index 10; local transmission completes, while the
Outstation execution count does not increase. This is same-project process
coverage, not independent-peer interoperability evidence.

There is no solicited application response for FC6. A successful local
transmission is not proof of remote execution; the CLI and tests do not treat
it as a successful remote command acknowledgment.

## Recorded execution

The final tested repository HEAD before committing the B3a tests was
`0b8026098e2c5564eb95eaa7641daf3b3425a52c`. The B3a test commit is
`a1d3ddcc096f329bdcc7f07da167a596eb0cb2e6`; it is on `develop` and contained
in `origin/develop`. Matrix `last_verified_revision` values point to the
reported tested HEAD, which contains the FC6 implementation exercised by the
tests.

The reported FC6-B3a Release build passed. The focused `[fc6-master]` run
passed 5 cases / 392 assertions. Final Windows Release CTest passed 8/8 in
110.00 seconds. The `pc-compat`, `pc-method4`, `pc-method68`, `pc-negative`
and `pc-tls` process scenarios passed. Test logs were supplied externally;
they are not committed repository artifacts. No full-suite assertion total is
claimed here.

Reproduction commands (with local build paths substituted):

```powershell
.\unittests.exe "[fc6-master]"
ctest.exe --test-dir <release-build-directory> -C Release --output-on-failure
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only compat
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only method4
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only method68
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only negative
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only tls
```

## Remaining boundaries

- FC6 is rejected in REQUIRED mode. Authenticated FC6's special
  challenge/aggressive handling under §7.5.2.3.2(i) is not implemented.
- No independent-peer interoperability test has been performed.
- Class-assignment wire auditing and broader FC3/FC4/FC5 control coverage
  remain open; the aggregate rows and Profile assessments were not promoted.
- The same-project TCP checks prove simulated Outstation invocation and
  readback in those scenarios only; they do not prove execution by a remote
  production device.
