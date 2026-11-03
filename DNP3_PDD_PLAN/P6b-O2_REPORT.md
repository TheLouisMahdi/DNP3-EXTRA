# P6b-O2 implementation and validation report

Status: **COMPLETE for the assigned native P6b-O2 implementation**, including the timestamp-blocker correction. Lack of synchronization does not inhibit events. A usable absolute occurrence time supports V2; no usable time produces an immutable V1 event for ordinary reporting. An explicit V2 request cannot convert an untimed historical event; its retention behavior is documented below. This is not an IEEE, SA v5, Level 4, or interoperability conformance claim.

## Initial baseline and change control

- Git root reported by Git: `D:/C drive/User/Desktop/DNP3-EXTRA` (the `C:/Users/poimu/Desktop/DNP3-EXTRA` workspace resolves to it).
- Branch: `develop`; initial and final HEAD: `6855ecad13407f9610870f5e5c8edb0cb5afbcdd`.
- Initially unstaged: `AGENTS.md` and the existing Catch assertion-parentheses workaround in `opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp`. Both remain untouched by O2. Staging was and remains empty.
- The task expressly authorized this phase's builds/tests and prohibited commits/pushes. No Git remote operation was performed and no remote synchronization is asserted.

## Requirements and applicability

Normative baseline: local `IEEE 1815/IEEE 1815-2012.pdf`, not a later edition. The supplied Device Profile `IEEE 1815/4812449245627490050_724147149003390.pdf`, PDF p12 (original p52), identifies G122V0/V1/V2 with the requested READ/RESPONSE/UNSOLICITED_RESPONSE qualifiers. That page and IEEE Table 12-63 were also rendered and visually inspected.

| Requirement | IEEE 1815-2012 reference, printed pages | O2 behavior |
| --- | --- | --- |
| Own-association statistics and indexes | 7.5.2.2, pp204-207; Table 7-6, pp206-207 | Indexes 0-17; association ID 0; Outstation index 17 stays zero. No cross-association reporting. |
| Reporting thresholds and special actions | 7.6.1.4.2, p242; Table 7-15, p243; Table 7-6 | Separate local reporting thresholds; approved provisional `delta >= threshold`; existing successful Session Key change forces index 2 reporting. No new authentication reactions. |
| Event classes and mandatory static reporting | 5.1.4, Tables 5-1/5-2, pp104-106 | Configurable Class 1/2/3; reject Class 0 and unknown/no-class values. G121 mandatory Class 0 remains unchanged. |
| Quality and continuity | 11.6, Table 11-5, pp322-326 | Mask reserved bits 5/7 (`0x5F`). Preserve O1's conservative DISCONTINUITY behavior. Rollover does not set DISCONTINUITY. |
| Synchronization and clock accuracy | 4.5.5, p83; 10.3.1-10.3.2, p298; 10.3.3, p299 | Missing synchronization must not inhibit functions. Preserve actual usable absolute clock readings, even when unsynchronized; NEED_TIME remains application-controlled. |
| Counter and reporting model | 11.9.10, Tables 11-19/11-20, pp349-350 | One AuthenticationStatistics counter source; native event snapshots only; no Database counter copies, freezing, or clearing. |
| Event wire layouts | A.47.1/A.47.2, pp760-763 | V1: 7-byte body; V2: 13-byte body with UINT48 occurrence time; little endian, index in prefix. |
| Qualifiers and function codes | Table 12-63, p374 | V0 READ: 00/01/06/17/28; V1/V2 READ: 06/07/08. Native responses use 28; generated serializers verified with both 17/28. Solicited 81 and unsolicited 82 verified. |

The security addendum ledger was read. G122 supports the supplied SA statistics scope; this does not discharge unrelated security-addendum, persistence, or full profile obligations.

## Native implementation

`AuthenticationStatistics::Increment` and `RequireReport` notify the new `IAuthenticationStatisticsReporter` synchronously at the actual condition. `SecurityStatEventPublisher` obtains `IDnpTimeSource::Now()` before returning to authentication, copies index/value/flags/association/time into an `Event<SecurityStatSpec>`, and submits it to `IEventReceiver`. The notification happens before a potentially slow retention Save. Reporting is acknowledged through the existing `ReportGenerated` only after actual native acceptance.

`OutstationConfig::securityStatThresholds` configures reporting deadbands independently of the existing protocol-Max configuration. Existing public aggregate member order is preserved before appending O2 fields. `securityStatConfig[0..17]` uses the existing `SecurityStatConfig`/`EventConfig` conventions for class and default event variation. Invalid classes/variations throw during construction. This does not implement remote ASSIGN_CLASS.

Existing modules reused: `SecurityStat`, measurement info/specs, `EventType`, `EventBufferConfig`, `IEventReceiver`, `EventLists`, `EventStorage`, `EventUpdate`, `EventSelection`, `EventBuffer`, `IEventSelector`, `ReadHandler`, `IEventWriteHandler`, `ASDUEventWriteHandler`, `EventWriters`, `HeaderWriter`, `ResponseContext`, and existing `OutstationStates` confirmation/retry/removal machinery. New dedicated module: `outstation/SecurityStatEventPublisher.{h,cpp}`. Context changes only connect ownership and post a coalesced notification through the existing executor; the occurrence callback does not transmit or reenter authentication. A weak lifetime guard cancels queued notification work after context destruction, and the runtime reporter is detached before destruction.

Native indexed/range selection is extended only for G122V0. Limited-count reads and class filters reuse existing selection. G122's default variation is restored on unselect so an expired explicit-V2 READ cannot change subsequent Class polling. Other event types retain existing behavior.

## Storage, overflow, and lifecycle

- `maxSecurityStatEvents` is a separate bounded native typed-list capacity. Default capacity is zero; configure it explicitly or use `EventBufferConfig::AllTypes(n)`. No second event queue/database is introduced.
- The legacy storage Update result means overflow, not acceptance. The G122 receiver checks nonzero capacity and validates own-association index/class/variation before insertion; only V2 requires usable occurrence time; its bool result explicitly means acceptance. Rejected events never advance the reporting baseline.
- At capacity, native EventUpdate drops the oldest same-type event, including a selected/written record if it is the oldest, and accepts the new snapshot. The native overflow latch/IIN records loss. It does not recursively increment security statistics or alter continuity flags. Previously serialized in-flight APDU bytes remain owned by the native transmission buffers.
- Accepted snapshots are copied by value; later counter/time changes cannot change events, fragments, or retransmissions. READ does not reconstruct historical timestamps or poll pending reporting conditions. A later real counter increment or forced occurrence can submit a fresh current snapshot after rejection; it does not recreate a rejected historical event.
- Matching native CONFIRMs clear written events; wrong/late CONFIRMs retain them. Existing solicited timeout, unsolicited retries, disconnect/reconnect, and multi-fragment continuation are used unchanged. Native 16-bit index/count response prefixes are emitted; 8-bit prefixes are also supported by HeaderWriter serializers.

## Timestamp blocker resolution

The original blanket synchronization gate was a confirmed defect in both `SecurityStatEventPublisher::Report` and `EventBuffer::Update(Event<SecurityStatSpec>)`. It rejected all events before enqueue when time was not SYNCHRONIZED, including V1, although V1 has no timestamp. Thus reporting conditions could remain pending indefinitely and later increments could replace the original occurrence instead of buffering it.

IEEE evidence re-examined: 4.5.5 (printed p83, also rendered and visually verified), 10.3.1-10.3.3 (pp298-299), 7.5.2.2 (pp204-207), 11.9.10/Table 11-19 (pp349-350), A.47.1/A.47.2 (pp760-763), Table 12-63 (p374), and the Device Profile PDF p12. Section 4.5.5 expressly prohibits function inhibition due to failure to receive synchronization; Table 11-19 makes timestamps optional. A.47.2 requires occurrence time, not response time. Section 10.3 distinguishes a dependable local clock from master synchronization and permits inaccurate reported times when synchronization is absent. Neither the profile nor A.47 mandates that every event wait for a synchronized clock.

| Clock at occurrence | Snapshot and ordinary Class/V0 reporting | Explicit G122V2 READ |
| --- | --- | --- |
| Synchronized, UINT48-representable UTC | Capture and preserve it; use configured V1/V2 default. | Use captured timestamp. |
| Usable absolute UTC, UNSYNCHRONIZED quality | Capture the real reading and preserve its internal quality. Use configured V1/V2; make no accuracy guarantee. | Use captured timestamp; do not relabel the internal snapshot synchronized. |
| INVALID, unknown quality, out-of-range, or throwing source | Store an immutable untimed snapshot with INVALID internal time and V1 default; no fabricated timestamp is emitted. | Do not convert, substitute V1, retime, or bypass the untimed event. Retain it for V1, V0, or Class polling. |

`SecurityStat::HasTime()` centralizes the distinction between usable absolute time and unavailable time. `SecurityStatEventPublisher` catches clock-source failure locally so it cannot reject a valid untimed counter event. It does not retry publication when the clock changes. The reporting baseline advances only on the same native acceptance result as before.

For explicit V2, native selection writes only the ordered timestamped prefix, up to the requested count, and stops at the first unselected untimed event. This avoids returning a newer event before an older event for the same point (5.1.5.1.2, p107). If there is no reportable V2 prefix, the response contains no event objects and retains the native Class-events IIN; no CONFIRM can delete the unwritten events. V1 or Class/V0 polling drains them. A later clock synchronization never reconstructs their missing occurrence time. Supported-type null-response handling follows the general Table 4-14 behavior (p85), rather than inventing OBJECT_UNKNOWN, PARAM_ERROR, or an authentication error. The choice to retain the ordered untimed prefix is an implementation policy; IEEE does not define a conversion that can recover nonexistent historical time. A V2-only poller cannot drain such a prefix and must use V1 or Class/V0. This unavoidable case-C representation limit is not concealed as a valid V2 event.

NEED_TIME remains owned by `IOutstationApplication::GetApplicationIIN`, as in native OpenDNP3. It requests time from the master; it is not a per-event accuracy bit. The tests verify propagation with and without the application flag in solicited/unsolicited responses, independent of snapshot quality and later clock changes. G122 does not automatically set or clear it when Now() quality changes. Section 4.5.5 requires support for time-write and G80V1 clearing/rearm when requesting time. Existing `WriteHandler` supports time writes but its G80V1 handler only clears DEVICE_RESTART; the broader NEED_TIME clear/rearm capability is a pre-existing gap outside this event-publication correction. Full time-service/NEED_TIME conformance is not claimed, and no system-wide clock or IIN lifecycle was added.

**P6b-O2-OPEN-01 is closed as a blanket-publication blocker.** P6-OPEN-01 remains open: 7.6.1.4.2's reporting boundary versus 11.9.10.2; retain the approved `>=`. P4-OPEN-01 and P6-OPEN-02/03, DISCONTINUITY clearing/rearming, platform retention, threshold persistence and absent Update Key producers remain unchanged. No Master decoding, ISOEHandler, G0V210, cross-association, authentication transition, TLS/crypto or embedded changes were made.

## Generation and static review

Compiled the repository's Scala 2.13.2 generator sources using Java 11 and ran the official `com.automatak.render.dnp3.Generate` entry point twice into separate isolated trees. The two entire output trees are byte-identical. O2 Group122 codec/metadata outputs match the source tree after line-ending/trailing-whitespace normalization; generated logic was not hand-authored. `GroupVariationSerialization.h` regenerated unchanged. Existing generated differences were left untouched: Group120/Group121 comment whitespace and StaticDoubleBinaryVariation's pre-existing `if` versus `else if` form. The system Java 21 compiler attempt failed; the cached Java 11 archive was truncated, so a fresh Java 11 JRE was obtained for the successful run. Build tools/archives are not source changes.

Reviewed the complete task diff and all new source files for ownership, bounded storage, baseline advancement, qualifier dispatch, scope, and unsafe fallbacks. `git diff --check`: PASS. A separate trailing-whitespace scan covers new untracked source files. No staging, broad formatting, application main.cpp test harness, secret, PDF reference, or compiled artifact was added to Git.

## Executed validation

Configuration: existing Visual Studio 17 2022 / MSVC x64 Release; `DNP3_SA_CRYPTO=ON`, `DNP3_TESTS=ON`.

| Check | Result |
| --- | --- |
| Fresh pre-O2 library and unit-test build | PASS, before source edits |
| Final-source OpenDNP3 library and unit-test build | PASS |
| New G122 cases | PASS: 22 cases, 208 assertions |
| Existing G121 cases | PASS: 8 cases, 889 assertions |
| Combined final G121/G122 run | PASS: 30 cases, 1097 assertions |
| Native event storage/responses/state-machine/unsolicited selection | PASS: 56 cases, 6206 assertions |
| Broader selected event/authentication regressions | FAIL: 11 cases, 60 assertions; final output byte-for-byte identical to fresh pre-O2 output |
| General Outstation tests | FAIL: 1 case/assertion at TestOutstation.cpp:403, the existing analog READ variation mismatch; same failure as archived O1/parent reports, not freshly rebuilt as a separate parent in O2 |
| Official generator repeatability and O2 output consistency | PASS, as qualified above |
| Whitespace/diff review | PASS |

The broader baseline comparison includes `AuthenticationRuntime` in addition to other authentication tests, explaining its broader failure count than the earlier handoff's 10-case/59-assertion selection. The existing Catch compatibility edit remained in place for both fresh baseline and O2 builds; it is not an O2 change. Deprecation warnings from existing LinkConfig tests and CMake dependency declarations are separate from O2 results.

Permanent tests inspect actual APDUs and cover exact codec bytes and both response qualifiers, truncated bodies/malformed headers, threshold equality/below threshold, modulo rollover, forced Session Key reporting, protocol-Max separation, zero-capacity rejection/pending baseline, overflow, immutable time/value snapshots, permitted READ qualifiers/indexes, all event classes/invalid classes, limited count, matching/wrong/late CONFIRM, timeout/retry, disconnect/reconnect, fragmentation, independent contexts, G121 isolation, configured variation restoration, and actual secure-context RX/TX accounting. No interoperability/Test Harness run, embedded build, or full conformance validation was performed.

Logs (workspace-relative, build outputs only): `build-p6b-o1/o2-baseline-build.log`, `build-p6b-o1/o2-baseline-tests.log`, `build-p6b-o2/build-verified.log`, `build-p6b-o2/test-g122.log`, `build-p6b-o2/test-security-final.log`, `build-p6b-o2/test-native-events.log`, `build-p6b-o2/test-baseline-comparison.log`, `build-p6b-o2/test-outstation-general.log`, and `build-p6b-o2/generator/`.

## Exact task paths

All paths below are relative to the Git root; the two initial user changes are excluded.

```
DNP3_PDD_PLAN/P6b-O2_REPORT.md
REPO_MAP.md
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/app/EventType.h
opendnp3/cpp/lib/include/opendnp3/app/MeasurementInfo.h
opendnp3/cpp/lib/include/opendnp3/app/SecurityStat.h
opendnp3/cpp/lib/include/opendnp3/gen/GroupVariation.h
opendnp3/cpp/lib/include/opendnp3/outstation/EventBufferConfig.h
opendnp3/cpp/lib/include/opendnp3/outstation/MeasurementConfig.h
opendnp3/cpp/lib/include/opendnp3/outstation/OutstationConfig.h
opendnp3/cpp/lib/src/app/MeasurementFactory.h
opendnp3/cpp/lib/src/app/MeasurementInfo.cpp
opendnp3/cpp/lib/src/app/MeasurementTypeSpecs.h
opendnp3/cpp/lib/src/app/WriteConversions.h
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp
opendnp3/cpp/lib/src/auth/AuthenticationStatistics.h
opendnp3/cpp/lib/src/gen/Attributes.cpp
opendnp3/cpp/lib/src/gen/GroupVariation.cpp
opendnp3/cpp/lib/src/gen/objects/Group122.cpp
opendnp3/cpp/lib/src/gen/objects/Group122.h
opendnp3/cpp/lib/src/outstation/EventBufferConfig.cpp
opendnp3/cpp/lib/src/outstation/IEventReceiver.h
opendnp3/cpp/lib/src/outstation/IEventSelector.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/OutstationContext.h
opendnp3/cpp/lib/src/outstation/ReadHandler.cpp
opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp
opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.h
opendnp3/cpp/lib/src/outstation/event/ASDUEventWriteHandler.cpp
opendnp3/cpp/lib/src/outstation/event/ASDUEventWriteHandler.h
opendnp3/cpp/lib/src/outstation/event/EventBuffer.cpp
opendnp3/cpp/lib/src/outstation/event/EventBuffer.h
opendnp3/cpp/lib/src/outstation/event/EventLists.cpp
opendnp3/cpp/lib/src/outstation/event/EventLists.h
opendnp3/cpp/lib/src/outstation/event/EventStorage.cpp
opendnp3/cpp/lib/src/outstation/event/EventStorage.h
opendnp3/cpp/lib/src/outstation/event/IEventWriteHandler.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestSecurityStatEvents.cpp
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/ObjectGroup.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group122.scala
```

## Timestamp-resolution validation and exact follow-up changes

The timestamp-resolution task changed only these existing O2 paths (no new module or queue):

- `opendnp3/cpp/lib/include/opendnp3/app/SecurityStat.h`: usable occurrence-time predicate.
- `opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp`: accept unsynchronized UTC, catch unavailable-clock failures, V1 default fallback.
- `opendnp3/cpp/lib/src/outstation/event/EventBuffer.cpp`: remove V1 clock gate; require usable time only for direct V2 insertion.
- `opendnp3/cpp/lib/src/outstation/event/EventStorage.cpp`: retain untimed prefix for explicit V2 without reordering.
- `opendnp3/cpp/tests/unit/TestSecurityStatEvents.cpp`: replace the obsolete blanket-block expectation and add focused clock-state/APDU/lifecycle tests.
- `REPO_MAP.md` and this report: update the resolved behavior and its limits.

Executed using the already verified MSVC x64 Release configuration and tool paths:

| Check | Timestamp-resolution result |
| --- | --- |
| OpenDNP3 and unittests build | PASS; final test-only incremental rebuild also passed |
| G122 tests | PASS: 30 cases, 275 assertions |
| G121 regressions | PASS: 8 cases, 889 assertions |
| Native event regressions | PASS: 56 cases, 6206 assertions |
| Relevant event/authentication regression selection | Same 11 failed cases / 60 failed assertions; byte-for-byte identical to recorded fresh committed O1 baseline (HEAD 6855ecad plus the existing excluded Catch workaround) |
| Scala generator | Official Generate rerun using existing compiled Scala 2.13.2 sources/Java 11; complete output byte-identical to prior verified generator tree. O2 generated source matches with only line-ending/trailing-whitespace normalization. No Scala or generated file changed in this follow-up. |
| Static scope and whitespace review | PASS, including new untracked source; existing AGENTS/Catch hashes preserved; staging empty |

The O1 comparison reuses the fresh pre-O2 build/run recorded earlier in this chat, avoiding a redundant full baseline build. The general Outstation analog READ failure in the preceding table is historical for this follow-up and was not rerun; it was not fixed or claimed passed. No interoperability/Test Harness, embedded or full conformance run occurred.

Clock tests exercise V1 without synchronization or absolute time, V2 with synchronized/usable unsynchronized UTC, actual occurrence-time immutability, unavailable/out-of-range/throwing clocks, default-V2 fallback under Class 1/2/3 and V0 polls, all explicit V2 READ count forms retaining untimed events, ordering across usable/unavailable/restored clocks, application NEED_TIME propagation, native buffer retention/removal, solicited timeout and unsolicited retransmission across clock changes, and no baseline advancement on zero-capacity rejection.

Follow-up logs and the initial changed-file hashes are under `build-p6b-o2/timestamp-resolution/`. They are build outputs, not staged source files.

## Required disposition

- P6b-O2: COMPLETE for the assigned native implementation and timestamp-publication correction; case-C explicit V2 cannot represent nonexistent time and retains events as documented.
- G122V1: VERIFIED, including absent/unsynchronized clocks.
- G122V2: VERIFIED for synchronized and usable unsynchronized absolute occurrence time; no invalid placeholder is emitted.
- G121: PRESERVED.
- MASTER G121/G122: NOT IMPLEMENTED. Generated low-level codecs are not Master dispatch/delivery.
- G0V210: NOT IMPLEMENTED.
- Ready for final review and a separately authorized controlled commit: YES, with the documented existing baseline failures and limits. No full IEEE/SA v5/Level 4 conformance claim.
- COMMIT: NOT CREATED.
- PUSH: NOT PERFORMED.
- Git root: `D:/C drive/User/Desktop/DNP3-EXTRA`; branch `develop`; HEAD `6855ecad13407f9610870f5e5c8edb0cb5afbcdd` unchanged. Staging: EMPTY. All existing O2/user work preserved. No push attempted; remote verification is not applicable.
