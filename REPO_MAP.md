# Repository Map

C++ DNP3 workspace: three console apps + local OpenDNP3 3.1.2 source.
Paths are relative to this root; section prefixes apply where stated.
Read this map first; open only relevant files. Update after structural changes.
The workspace root is the current Git repository; `opendnp3/` is its library subtree.
Map baseline: branch `develop`, commit `77980d5a68a1e58e854ed9e6787585a2a75774cb`.

Status labels: IMPLEMENTED = the native vertical slice exists here and has been reviewed;
VERIFIED = a report in `DNP3_PDD_PLAN/` records executed passing tests for that slice.
Neither label asserts IEEE 1815, Level 4, SA v5 or Test Harness conformance.

## Entry Points
- `apps/master/main.cpp` → TCP client, polls, commands, measurement callbacks.
- `apps/outstation/main.cpp` → TCP server, point configuration, simulated updates.
- `cli/main.cpp` → interactive diagnostic Master/Outstation CLI (`cli/README.md`); no SA.
- `opendnp3/cpp/lib/src/DNP3Manager.cpp` → library startup and channel creation.

## Core
Prefix: `opendnp3/cpp/lib/src/`
- `master/` → polling, command tasks, scheduling; start at `MasterContext.cpp`.
- `master/CommandSet.cpp`, `CommandSetOps.cpp`, `CommandTask.*`, `TypedCommandHeader.h` → G12/G41 typed SELECT/OPERATE/DIRECT_OPERATE request building and per-point response state.
- `master/MeasurementHandler.*` → typed SOE delivery for measurements, G121/G122 and G0 attributes; preserves raw indexes, Association ID and header metadata.
- `outstation/` → request handling, responses, unsolicited reporting; start at `OutstationContext.cpp`.
- `outstation/CommandResponseHandler.h`, `CommandActionAdapter.h`, `ControlState.h`, `RequestHistory.*` → command dispatch to `ICommandHandler`, per-select state and exact retry identity.
- `outstation/ReadHandler.h`, `WriteHandler.h` → object request dispatch; narrow whitelist guards keep partially invalid mixed WRITEs side-effect free.
- `outstation/Database.cpp` → in-memory point selection, updates, static responses.
- `outstation/event/` → event buffering and response serialization.
- `outstation/UpdateBuilder.cpp` → application measurement update batches.
- `app/` → APDU construction, object headers, measurement serialization.
- `app/parsing/APDUParser.cpp` → parsing, handler dispatch and per-group qualifier gates (G51 CTO qualifier 07; G0 request/response qualifiers; G122 READ forms; G120 free-format/UINT8 count). `CountParser.cpp` enforces G51 count 1; `CountIndexParser.*`/`RangeParser.*` supply indexed/range bodies.
- `app/parsing/DeviceAttributeParser.*`, `app/DeviceAttribute.h` (public include), `app/HeaderWriter.*` → native G0V209/V210 UINTn and V254/V255 list parsing/writing; attribute-set indexes remain separate from security associations.
- `outstation/DeviceAttributeSelection.*` → bounded standard-set V210 capability and mandatory V254/V255 discovery. V209 remains unadvertised until a complete SA version is supported.
- `crypto/CryptoProvider.h` → shared internal cryptographic buffer interface.
- `crypto/OpenSSLCryptoProvider.cpp` → optional OpenSSL SA primitives; see `crypto/README.md`.
- `auth/SessionKeys.*`, `auth/AuthenticationSession.*` → bounded session-key lifecycle and authorization boundary.
- `auth/AggressiveMode.*` → authenticated V3/V9 envelopes, separate solicited/unsolicited challenge histories and replay checks.
- `auth/RemoteUpdateKeys.*`, `auth/UpdateKeyFunctions.*` → opt-in, bounded Method 4/68 remote credential/user lifecycle and IEEE transcripts; `master/UpdateKeyTask.*` reuses native task scheduling.
- `auth/WindowsAuthenticationCredentials.cpp` → legacy retrieval plus remote-user journal in Windows Credential Manager; trusted clock supplied by the provisioning application.
- `auth/AuthenticationStatistics.*` → G121 association counters, reporting baselines, five protocol maxima, frozen READ snapshots and synchronous G122 occurrence notifications.
- `outstation/SecurityStatEventPublisher.*` → copies G122 occurrence snapshots into the native bounded event buffer (application DNP time, Class 1/2/3 config).
- `master/MasterResponder.*`, `outstation/OutstationChallenger.*` → Control/Monitoring challenge-response cores.
- `transport/` → fragment segmentation/reassembly.
- `link/` → frames, CRC, link state; start at `LinkContext.cpp`.
- `decoder/`, `logging/`, `util/` → diagnostics and shared helpers.

## Feature Status (Outstation / Master)

- G120 SA v5 (`auth/`, `app/parsing/APDUParser.cpp`): IMPLEMENTED only as challenge-response, session-key and aggressive-mode exchanges. Full SA v5 is incomplete and never advertised; G0V209 is therefore unavailable (OBJECT_UNKNOWN, omitted from discovery).
- G121 statistics: Outstation READ/Class 0 IMPLEMENTED and VERIFIED (`P6b-O2_REPORT.md`); Master typed decode/delivery IMPLEMENTED and VERIFIED (`P6b-M1_REPORT.md`).
- G122V1/V2 events: Outstation selection/publication/CONFIRM IMPLEMENTED and VERIFIED (`P6b-O2_REPORT.md`); Master prefix/range decode IMPLEMENTED and VERIFIED (`P6b-M1_REPORT.md`).
- G0V210 plus V254/V255 discovery: IMPLEMENTED and VERIFIED on both roles (`P6c_REPORT.md`). G0V209: Master decode VERIFIED; Outstation deliberately unsupported.
- Measurements/events G1/G2/G3/G4/G10/G30/G32/G40 (31 profile rows): IMPLEMENTED, not VERIFIED per row (`DEVICE_PROFILE_MEASUREMENTS_REPORT.md`). G2V3/G4V3 relative CTO validation has focused passing tests.
- Controls G12V1/G41V1-V3: IMPLEMENTED and committed at `77980d5` — selection lifecycle, exact retry identity and Master SELECT echo guard included; `[profile-controls]` 21 cases/588 assertions plus 50 command-regression cases PASS (user-run, `DEVICE_PROFILE_MEASUREMENTS_REPORT.md`). Not VERIFIED: no interoperability, Test Harness or full profile/IEEE conformance run.

## Interfaces and Configuration
Prefix: `opendnp3/cpp/lib/include/opendnp3/`
- `DNP3Manager.h`, `channel/IChannel.h` → public manager/channel API.
- `master/` → master API/callbacks; `MasterStackConfig.h` configures the stack, `ISOEHandler.h` receives measurements plus default-no-op typed G121/G122 and G0 attribute overloads.
- `outstation/` → outstation API/callbacks; `OutstationStackConfig.h`, `DatabaseConfig.h`, `EventBufferConfig.h` (including `maxSecurityStatEvents`), `OutstationConfig.h` (`securityStatConfig[18]`, `securityStatThresholds`) configure points/events/statistics.
- `outstation/ICommandHandler.h`, `IOutstationApplication.h` → control/application integration hooks; point models, pulse timing, interlocks and NEED_TIME stay application-owned.
- `outstation/UpdateBuilder.h` → measurement update API.
- `channel/`, `link/LinkConfig.h` → endpoint, serial, TLS, retry and addressing settings.
- `auth/AuthenticationConfig.h` → explicit secure/compatibility modes, users, credential retrieval and APDU authorization.
- `auth/SecurityStatistic.h` → IEEE indexes/default thresholds and portable durable-retention interface.
- `auth/WindowsAuthenticationCredentials.h` → Windows credential format and expiry contract.
- `auth/UpdateKeyConfig.h` → durable users, Outstation-only authority trust and Master authority-material boundary; no production authority keys or external distribution protocol.
- `app/` → public measurement, command, `SecurityStat.h` and `DeviceAttribute.h` types.

Runtime endpoints and stack settings live in the app entry points.
The outstation database is in memory; the apps simulate measurements and accept controls without a custom hardware adapter.
Adding `ISOEHandler` virtuals and G121/G122/G0 typed overloads is source-compatible but requires binary clients to rebuild.

## Network / Device I/O
- `opendnp3/cpp/lib/src/channel/DNP3Channel.cpp` → channel-to-stack assembly.
- `opendnp3/cpp/lib/src/channel/` → TCP, UDP, serial I/O handlers.
- `opendnp3/cpp/lib/src/channel/tls/` → optional OpenSSL transport.

## Tests
Prefix: `opendnp3/cpp/tests/`
- `unit/` → protocol/state tests; `TestAPDUParsing.cpp`, `TestDatabase.cpp` are parser/database starting points.
- `unit/TestProfileMeasurements.cpp` (`[profile-measurements]`) → G2V3/G4V3 CTO validation, typed time quality, malformed-fragment rejection, native confirmations.
- `unit/TestProfileControls.cpp` (`[profile-controls]`) → G12/G41 wire controls, exact SBO/retry identity, selection cancellation, malformed commands, statuses, Master echo/IIN checks; 21 cases PASS (user-run, 588 assertions).
- `unit/TestDeviceAttributes.cpp` (`[device-attributes]`) → G0 wire formats, actual per-association count, discovery, malformed data, typed Master delivery, fragmentation/WRITE protection.
- `unit/TestMasterSecurityStatistics.cpp` (`[master-security-statistics]`) → Master G121/G122 qualifiers, typed callbacks, association isolation, occurrence time, malformed fragments, mixed-WRITE rejection.
- `unit/TestSecurityStatEvents.cpp` (`[security-stat-events]`) → G122 codecs, reporting, READ selection, event classes, native responses/CONFIRMs/retries, fragmentation, clock-state cases.
- `unit/TestRemoteUpdateKeys.cpp` (`[remote-update-keys]`) → Methods 4/68 native runtime, independent cryptographic vectors, persistence faults/recovery, authority/role/expiry/replay checks and actual G121/G122 accounting; `integration/TestSecureAuthentication.cpp` (`[remote-update-tcp]`) exercises both methods across real TCP reconnect/restart.
- `dnp3mocks/` → shared mocks and stack fixtures (`MockSOEHandler` implements the new overloads).
- `asiotests/` → asynchronous I/O tests. `integration/` → stack integration tests. `fuzz/` → parser fuzz targets.
Enable C++ tests with `DNP3_TESTS`; fuzz targets use `DNP3_FUZZING`.
`DNP3_SA_CRYPTO` enables SA cryptographic and runtime components independently of TLS.
Stacks require credentials and an authorization policy by default; legacy operation must explicitly
select `AuthenticationConfig::Mode::COMPATIBILITY`. Required SA fails closed when crypto or credentials
are unavailable. `integration/TestSecureAuthentication.cpp` (`[sa-tcp]`) covers real local TCP
READ/CONTROL, count renewal, reconnect and Outstation restart with ephemeral keys.

## Known Open Issues
Unresolved or deliberately deferred work; details live in the linked reports, not here.
- `P4-OPEN-01` → G120V7 code 5/7 meaning conflict (Annex A.45.7.2.2 vs 7.5.5.7); provisional code 5 = MAC not supported, 7 = authorization failed.
- `RUK-OPEN-01` → SCS monotonicity versus wrap (7.5.5.5 versus A.45.10); all remote resets/wrap are rejected across certification methods and authority-key changes. Named tombstones are retained. See `DNP3_PDD_PLAN/SA_REMOTE_UPDATE_KEYS_REPORT.md`.
- `RUK-OPEN-02` → A.45.14 does not specify DSA r/s wire representation; Method 68 provisionally uses strict DER per RFC5758/3279. Independent interoperability remains required.
- `P6-OPEN-01` → G121 reporting threshold boundary (7.6.1.4.2 vs 11.9.10.2); approved provisional `delta >= threshold`.
- G121 continuity → without a successful initial retention load snapshots keep DISCONTINUITY; per-point acquisition/transmission rearming and a platform retention backend are missing. Rollover does not set DISCONTINUITY.
- NEED_TIME → `WriteHandler` G80V1 only clears DEVICE_RESTART; clear/rearm on time request is a pre-existing gap.
- G122 explicit V2 → untimed historical events are retained unchanged (V1/Class/V0 only); case-C representation limit in `P6b-O2_REPORT.md`.
- G0V209 → Outstation cannot advertise any SA version yet; discovery excludes it.
- Master commands → typed function 6 (no-response) API intentionally absent; generic `PerformFunction` awaits a response.

## Build and Optional Components
- `CMakeLists.txt` → builds local library, `master`, `outstation`, and `cli/`.
- `opendnp3/CMakeLists.txt` → library version, optional tests/examples/TLS/bindings, CPack packaging.
- `opendnp3/cpp/lib/CMakeLists.txt` → library source list, linking, installation.
- `opendnp3/deps/*.cmake` → dependency acquisition declarations; inspect only for dependency/build work.
- `opendnp3/cmake/` → formatting, linting, coverage helpers.
- `opendnp3/.github/workflows/ci.yml` → upstream build/test/package workflow.
- `opendnp3/cpp/examples/` → optional reference apps; separate from workspace apps.
- `opendnp3/java/`, `opendnp3/dotnet/` → optional language bindings and their builds.
- `opendnp3/generation/` → Maven/Scala code generators; protocol models under `dnp3/src/main/scala/com/automatak/render/dnp3/` (`objects/groups/Group0|12|41|120|121|122.scala`, `objects/ObjectGroup.scala`), shared renderers under `render/`.

## Requirements Navigation
- `DNP3_PDD_PLAN/README.md` → planning scope, evidence labels and reading order.
- `DNP3_PDD_PLAN/01_SOURCE_MAP.md` → standards/profile PDF page index, not a code index.
- `DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv` → requested object/variation matrix.
- `DNP3_PDD_PLAN/03_SECURITY_MATRIX.md` → security requirements.
- `DNP3_PDD_PLAN/04_G0V209_CONTRACT.md` → device-attribute contract and its P6c resolution.
- `DNP3_PDD_PLAN/05_PHASES_AND_CODEX.md` → implementation sequence and task-status vocabulary.
- `DNP3_PDD_PLAN/06_PREVIOUS_GUIDELINE_AUDIT.md` → corrections to the earlier draft.
- `DNP3_PDD_PLAN/P6b-O2_REPORT.md` → G121 READ and G122 event publication, clock/continuity limits.
- `DNP3_PDD_PLAN/P6b-M1_REPORT.md` → Master G121/G122 parsing, typed delivery, qualifier whitelists.
- `DNP3_PDD_PLAN/P6c_REPORT.md` → G0V209/V210 and V254/V255 attributes.
- `DNP3_PDD_PLAN/DEVICE_PROFILE_MEASUREMENTS_REPORT.md` → G1/G2/G3/G4/G10/G30/G32/G40 rows plus G12/G41 control rows.
Planning documents and reports describe requirements or past tasks, not current verified support.

## Dependency Flow
- Build: root CMake → OpenDNP3 library → console apps link it.
- Startup: app → DNP3Manager → channel → master/outstation stack.
- Protocol: master/outstation ↔ app encoding/parsing ↔ transport ↔ link ↔ channel I/O.
- Measurements: outstation app → UpdateBuilder → Database/event buffer → responses → master ISOEHandler.
- Statistics: authentication → AuthenticationStatistics → SecurityStatEventPublisher → event buffer → G122; or frozen snapshot → G121 READ → Master MeasurementHandler.
- Generation: Scala models/renderers → generated C++ enums/objects.

## Ignore During Discovery
- `build/`, `build-*/`, `**/build/`, `dist/`, `target/`, `bin/`, `obj/`, `_deps/` → outputs, logs/dependency caches.
- `.git/`, `.freebuff/`, caches, virtual environments, logs, temporary files, binaries.
- `opendnp3/cpp/lib/src/gen/`, `opendnp3/cpp/lib/include/opendnp3/gen/` → generated; use generator sources first.
- `IEEE 1815/` → reference PDFs; consult the planning page index only when standards work requires them.
- `steps/` → currently empty.
