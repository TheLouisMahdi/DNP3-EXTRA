# Device Profile measurement/event coverage

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

## Exact changed paths

```
DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv
DNP3_PDD_PLAN/DEVICE_PROFILE_MEASUREMENTS_REPORT.md
REPO_MAP.md
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/app/parsing/CountParser.cpp
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestProfileMeasurements.cpp
```
