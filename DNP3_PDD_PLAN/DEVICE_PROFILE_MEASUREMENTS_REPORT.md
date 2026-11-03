# Device Profile measurement/event and control coverage

Baseline: `develop`, `39e175da7716bb14745e62773107181a1a00dd41`. Scope: 31 rows for G1/G2/G3/G4/G10/G30/G32/G40. IMPLEMENTED; focused manual validation and final review PASS. Builds/tests were executed by the user, not the agent. All 31 rows retain IMPLEMENTED status; no complete per-row VERIFIED claim. Existing AGENTS.md and Catch edits are excluded. No push.

## Coverage

All 31 selected matrix rows are IMPLEMENTED, not VERIFIED. Source inspection establishes the native paths below. Existing tests or a focused CTO run do not prove every function/qualifier/variation at runtime. Other matrix rows are unchanged. Extra existing variations do not enlarge the selected product requirements.

| Profile rows | Selected variations and encoding | Native paths reused | Status |
| --- | --- | --- | --- |
| 003-005: G1 | V0 default/assignment; V1 packed 1-bit state; V2 state/flags octet | BinarySpec Database selection, StaticWriters, RangeParser, Binary callback, AssignClassHandler | IMPLEMENTED |
| 006-009: G2 | V0 default; V1 state/flags; V2 plus UINT48 time; V3 plus UINT16 offset/CTO | EventBuffer Binary selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, Binary callback, MeasurementHandler CTO | IMPLEMENTED; malformed CTO dependency fixed |
| 010-012: G3 | V0 default/assignment; V1 packed 2-bit states; V2 state/flags octet | DoubleBitBinarySpec Database selection, DoubleBitfieldRangeWriteIterator/StaticWriters, RangeParser, DoubleBitBinary callback, AssignClassHandler | IMPLEMENTED |
| 013-016: G4 | V0 default; V1 state/flags; V2 plus UINT48 time; V3 plus UINT16 offset/CTO | EventBuffer DoubleBitBinary selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, DoubleBitBinary callback, MeasurementHandler CTO | IMPLEMENTED; malformed CTO dependency fixed |
| 017-018: G10 | V0 default; V2 output status/flags octet | BinaryOutputStatusSpec Database selection, StaticWriters, RangeParser, BinaryOutputStatus callback | IMPLEMENTED |
| 020-025: G30 | V0 default/assignment; V1 flags+INT32; V2 flags+INT16; V3 INT32; V4 INT16; V5 flags+FLT32 | AnalogSpec Database selection, StaticWriters/WriteConversions, RangeParser, Analog callback, AssignClassHandler | IMPLEMENTED |
| 026-030: G32 | V0 default; V1 flags+INT32; V2 flags+INT16; V4 flags+INT16+UINT48 time; V5 flags+FLT32 | EventBuffer Analog selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, Analog callback | IMPLEMENTED |
| 031-034: G40 | V0 default; V1 flags+INT32; V2 flags+INT16; V3 flags+FLT32 | AnalogOutputStatusSpec Database selection, StaticWriters/WriteConversions, RangeParser, AnalogOutputStatus callback | IMPLEMENTED |

Exact source prefix: `opendnp3/cpp/lib/src/`:

- Static READ: `outstation/ReadHandler.cpp`, `outstation/Database.cpp::SelectAll/SelectRange`, `outstation/StaticDataMap.h::select_all/select`, `outstation/StaticWriters.cpp`.
- Event READ/publication: `outstation/event/EventBuffer.cpp::SelectMaxCount`, `EventSelection.h::SelectByTypeGeneric`, `ASDUEventWriteHandler.cpp`, `EventWriters.h` in that directory. Bounded occurrence snapshots and overflow use `EventUpdate.h`, `EventStorage.cpp`, `EventWriting.cpp`; native `outstation/ResponseContext.cpp` and response states own fragmentation/confirmation/removal. These modules are unchanged.
- Master decode: `app/parsing/RangeParser.{h,cpp}`, `CountIndexParser.{h,cpp}`, `app/MeasurementFactory.h`, `app/MeasurementTypes.cpp`, `master/MeasurementHandler.{h,cpp}` and public `opendnp3/master/ISOEHandler.h`.
- Class assignment: `outstation/AssignClassHandler.cpp`, `Database.cpp::AssignClassToAll/AssignClassToRange`, `StaticDataMap.h::assign_class`; application RecordClassAssignment remains native. No new persistence guarantee.
- Models/codecs: `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group{1,2,3,4,10,30,32,40}.scala` and `gen/objects/Group{1,2,3,4,10,30,32,40}.{h,cpp}`. All 16 codec files match existing official P6c generator output after whitespace normalization. No regeneration/generated edits.

## Functions, qualifiers and behavior

Static READ function 1: 00/01/06; RESPONSE 129: 00/01. Selected G1V0/G3V0/G30V0 also support ASSIGN_CLASS 22 with 00/01/06 and native class-header sequencing. G10/G40 rows describe status, not control commands.

Event READ function 1: 06/07/08 for V0 and selected explicit variations; native count selection bounds quantity. RESPONSE 129 and UNSOLICITED_RESPONSE 130: 17/28. Outstation writes 28; Master parses both widths. Scheduling, retries, confirmations and event removal remain native/configuration dependent. No duplicate-delivery policy changes.

V0 selects configured variations and is not a response body. Numeric encodings are little-endian; packed states are low-bit first with zero padding. `outstation/StaticDataMap.cpp::check_for_promotion` already preserves abnormal quality by promoting G1V1 to V2, G3V1 to V2, and G30V3/V4 to V1/V2. Flagless receive values assume online. Existing WriteConversions/DownSampling provide narrowing/overrange behavior. Raw point indexes and typed callbacks are retained.

G2V3/G4V3 use the preceding CTO in the same fragment. CTO V1/V2 conveys synchronized/unsynchronized quality; Outstation EventWriters starts another CTO/header on backward time, oversized UINT16 offset or quality change. Event occurrence values remain independent of later database updates.

## IEEE/profile references and confirmed gap

Device Profile PDF pp4-8 and matrix rows above. IEEE 1815-2012 Tables 12-2/3/4/5/6/14/16/19 (printed pp352-358); A.2 (pp488-489), A.3 (pp490-492), A.4 (pp493-494), A.5 (pp495-497), A.6.2 (p500), A.14.1-5 (pp565-569), A.16.1/2/4/5 (pp581-582,585-587), A.19.1-3 (pp610-612). Related types/flags/float: 11.9.1/2/4/6/8, 11.6, 11.3.5. Product-selected objects apply even when beyond Level 3 minimums; no full Level 4 claim.

Confirmed gap: IEEE Table 12-23 (printed p360) requires CTO qualifier 07, quantity 1; A.3.3/A.5.3 and A.24 (pp654-657) define the preceding reference. Baseline parser accepted multi-value/08 CTO headers and all-objects 06 markers. MeasurementHandler ignored multi-value CTOs, retaining an earlier reference; malformed input could deliver relative events with stale timestamps.

Fix: APDUParser rejects response G51 qualifiers other than 07; CountParser rejects CTO quantities other than 1 on the first validation pass. This necessary G51 dependency is the only protocol change. No partial callbacks or unsolicited confirmation on malformed fragments. Valid CTO paths, no-contents READs and ordinary event limited counts remain unchanged. G120/G121/G122, SA state machines, TLS and G0V209 are untouched.

## Tests and validation

`opendnp3/cpp/tests/unit/TestProfileMeasurements.cpp`, `[profile-measurements]`: 8 permanent cases, manually executed by the user: PASS, 160 assertions, exit code 0. Covers valid G2V3/G4V3 with both prefix widths/CTO qualities; next CTO replacement; malformed quantities/08/06 with preceding measurement/reference; zero/truncated CTOs; ordinary event limited READs; malformed native unsolicited no-delivery/no-CONFIRM; valid native solicited fragment CONFIRMs.

Manual validation supplied by the user in this chat:

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including dependencies | PASS; exit code 0 |
| `[profile-measurements] -r compact` | PASS; 8 cases / 160 assertions; exit code 0 |
| `*APDUParsing*,*MeasurementHandler*,*ReadGrp2Var3* -r compact` | PASS; 46 cases / 193 assertions; exit code 0 |
| Focused final review and scoped/staged whitespace checks | PASS; no additional confirmed defect |

The build emitted dependency FetchContent deprecation warnings; it completed successfully. Later shell errors came from pasted prompt/output text after the successful focused run, not from the executable. No agent build/test execution. Existing tests outside the exact filters above were not rerun; prior-phase results are not substituted for this task's validation.

Successful manual validation and final review satisfy the authorization for one local commit containing only the seven paths below; the commit hash is recorded in the final chat response. Existing AGENTS.md and Catch edits remain excluded. No push. Full per-row protocol/interoperability verification remains outstanding, so all selected coverage stays IMPLEMENTED rather than VERIFIED.

## Measurement/event changed paths (previous commit)

```
DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv
DNP3_PDD_PLAN/DEVICE_PROFILE_MEASUREMENTS_REPORT.md
REPO_MAP.md
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/app/parsing/CountParser.cpp
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestProfileMeasurements.cpp
```

## Control command completion

Current baseline: `develop`, `77980d5a68a1e58e854ed9e6787585a2a75774cb`. This extension adds profile rows 019 and 035-037 to the coverage above. Status: IMPLEMENTED, committed at that baseline and validated by the focused tests below. Earlier measurement/event test results above are historical and are not control validation. Not VERIFIED: no interoperability, Test Harness, embedded or full profile/IEEE conformance run.

| Profile row | Applicable behavior and native evidence | Status |
| --- | --- | --- |
| 019, G12V1 CROB | code/count UINT8, on/off UINT32, status UINT8; Master CommandSet/CommandTask/TypedCommandHeader; Outstation CommandResponseHandler/CommandActionAdapter/ICommandHandler | IMPLEMENTED |
| 035, G41V1 | INT32 followed by UINT8 command status; same native command machinery and typed AnalogOutputInt32 callbacks | IMPLEMENTED |
| 036, G41V2 | INT16 followed by UINT8 command status; typed AnalogOutputInt16 callbacks | IMPLEMENTED |
| 037, G41V3 | IEEE FLT32 followed by UINT8 command status; typed AnalogOutputFloat32 callbacks | IMPLEMENTED |

Native source prefix: `opendnp3/cpp/lib/src/`. Models are `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group12.scala` and `Group41.scala`; generated codecs in `gen/objects/Group12.{h,cpp}` and `Group41.{h,cpp}` match existing official P6c generator evidence after whitespace normalization. No generator/model/codec change or regeneration. `app/parsing/CountIndexParser` supplies two-pass indexed command parsing; `master/CommandSet.cpp`, `CommandSetOps.cpp`, `TypedCommandHeader.h`, `CommandTask.cpp` and `outstation/CommandResponseHandler`, `CommandActionAdapter`, `OutstationContext` supply the existing vertical path. Existing permanent MasterCommandRequests, MasterMultiCommandRequests, TypedCommandHeader and OutstationCommandResponses tests are retained.

Both request qualifier widths 17/28 are reused, with corresponding echoed response headers/indexes. Outstation SELECT/OPERATE/DIRECT_OPERATE/DIRECT_OPERATE_NR functions 3/4/5/6 are parsed and dispatched through the native command interface. Function 6 sends no command response. Master typed SELECT/OPERATE (3/4) and DIRECT_OPERATE (5) remain supported. The supplied profile targets an Outstation; Master function 6 issuance is optional. The user explicitly chose to preserve the native Master API: no typed function 6 API or authenticated no-response task lifecycle is added. Generic PerformFunction is not advertised as a correct no-response command API because it awaits a response.

IEEE 1815-2012: 4.4.4/4.4.4.1-3, Rules 1-9 and Tables 4-9/4-10 (printed pp48-54); 4.4.5 (pp54-55); Table 12-8 (p354), Table 12-20 (p358); A.8.1 (pp505-510, including Table A-1/A-2 and the obsolete QU rule), A.20.1-3 (pp615-617). Device Profile PDF pp3,6,8. Hardware-specific point models, pulse timing, zero-count behavior, interlocks, allowed analog ranges and actual physical execution remain application ICommandHandler responsibilities; this task does not invent a hardware model or treat a successful wire response as proof of physical movement.

### Confirmed gaps and minimal fixes

- Partial SELECT acceptance: objects rejected as TOO_MANY_OPS were not counted, making AllCommandsSuccessful true after a partially rejected batch. Count every request object, including rejected objects; a failed SELECT cannot arm OPERATE.
- Selection lifecycle: intervening requests did not cancel a selection; a successful OPERATE did not consume it; failed new SELECTs and link loss could leave stale state. Apply Table 4-9 after authentication admission, cancel/consume native selection as appropriate, and clear on disconnect. A changed same-sequence SELECT is discarded; an exact retry uses the cached response without restarting the timer. Native timeout remains exclusive at the configured boundary. Existing maxRx/maxTx checks and command limits remain in force; empty control requests now return PARAM_ERROR (or no response for function 6) without callbacks.
- Exact identity: ControlState and RequestHistory used only length plus CRC-16. Distinct, valid same-length commands with a CRC collision could substitute for selected output values or be mistaken for retries. Replace fingerprint-only identity with owned byte snapshots. Both buffers are allocated once per Outstation using the existing configured maxRxFragSize; total additional payload storage is twice that limit (4096 bytes at default 2048). Normal parsing/retry requests do not allocate new buffers. Oversize command bodies are rejected before callbacks.
- Master SELECT guard: typed value comparisons did not enforce the complete wire echo, so raw CROB differences, float signed-zero changes or extra objects could permit OPERATE. CommandTask retains the successfully formatted SELECT body (bounded by its existing TX buffer) and refuses OPERATE unless response bytes match and IIN2.0/2.1/2.2/2.4 are clear. Existing per-point failure callbacks remain native. TypedCommandHeader compares raw CROB and floating-point fields on both response legs, while CommandSetOps observes handler errors for SELECT and OPERATE/direct responses. This snapshot allocates once for a SELECT task, not per response.
- ALREADY_ACTIVE status 5 lacked IIN2.4; set ALREADY_EXECUTING as required by Table 4-10. Existing NOT_SUPPORTED/PARAM_ERROR handling is retained; local-control IIN still comes from the application.

Same-sequence authenticated SELECT retries/discards must not transfer ownership. The two existing validated-user binding sites (challenge/reply and aggressive request release) now retain the original selectUser whenever native ControlState identifies that SELECT sequence. Policy authorization, MAC verification, replay checking, key state and the OPERATE user comparison remain unchanged and precede native dispatch. No unauthenticated fast path, alternate execution path or authentication state machine is added. No changes to G120/G121/G122 codecs, statistics, event publication, TLS or G0V209.

### Focused permanent tests and current validation

`opendnp3/cpp/tests/unit/TestProfileControls.cpp`, `[profile-controls]`: 21 permanent cases, PASS (user-run): 21 cases / 588 assertions, exit code 0. Covers all four selected variations and both index widths; functions 3/4/5/6 on the Outstation; Master SBO; command limits; failed/intervening/new selections; exact retry timer boundary; duplicate execution prevention; CRC-collision substitution and retry identity; reconnect; command statuses/IIN; malformed/truncated/empty requests with no partial callbacks; Master error IIN, extra/truncated echo, raw CROB and signed-zero mismatch; failed SELECT statuses; no automatic control retries on timeout; bounded snapshot ownership/sequence wrap.

Existing authenticated operation/policy/ownership tests were selected narrowly for command regression (50 cases / 235 assertions); no broad SA suite was run. The new bounded-selection unit case is not a new MAC/SA integration result. Existing historical authentication baseline failures remain historical; do not infer a new pass/fail from them. All four rows stay IMPLEMENTED, not VERIFIED; targeted tests do not establish physical operation, full profile/IEEE conformance or independent interoperability.

Current manual build/test: PASS. Static review and `git diff --check`: PASS.

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including dependencies | PASS |
| `[profile-controls] -r compact` | PASS; 21 cases / 588 assertions; exit code 0 |
| Command regression selection | PASS; 50 cases / 235 assertions; exit code 0 |
| Combined validated total | PASS; 71 cases / 823 assertions |

The control implementation, its permanent test file and the test registration are committed at `77980d5a68a1e58e854ed9e6787585a2a75774cb`; no control code is left in the working tree. Remote synchronization is recorded in the final chat response. Independent AGENTS.md and Catch edits remain excluded.

## Control command changed paths (commit `77980d5`)

```
DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv
DNP3_PDD_PLAN/DEVICE_PROFILE_MEASUREMENTS_REPORT.md
REPO_MAP.md
opendnp3/cpp/lib/src/master/CommandSetOps.cpp
opendnp3/cpp/lib/src/master/CommandTask.cpp
opendnp3/cpp/lib/src/master/CommandTask.h
opendnp3/cpp/lib/src/master/TypedCommandHeader.h
opendnp3/cpp/lib/src/outstation/CommandResponseHandler.h
opendnp3/cpp/lib/src/outstation/ControlState.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/RequestHistory.cpp
opendnp3/cpp/lib/src/outstation/RequestHistory.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestProfileControls.cpp
```
