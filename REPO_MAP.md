# Repository Map

C++ workspace with two TCP demos, a Windows diagnostic CLI and vendored OpenDNP3 3.1.2. The Git root is the workspace root. `opendnp3/` is the library subtree. Start with `AGENTS.md`, then open the paths for the task at hand.

Path shorthand in this map is exact. `src/` expands to `opendnp3/cpp/lib/src/`, `api/` to `opendnp3/cpp/lib/include/opendnp3/`, and `tests/` to `opendnp3/cpp/tests/`. The `groups/` prefix expands to `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/`. Other paths are workspace-relative.

## Entry points and build

| Path | Purpose |
| --- | --- |
| `apps/master/main.cpp` | TCP client demo with polls, controls and measurement callbacks. |
| `apps/outstation/main.cpp` | TCP server demo with simulated points and command handling. |
| `cli/main.cpp`, `cli/Security.cpp`, `cli/README.md` | Windows diagnostic Master and Outstation over TCP or mutual TLS. Explicit compatibility or SA Methods 4/68. See the README for build flags and commands. |
| `CMakeLists.txt`, `opendnp3/CMakeLists.txt`, `opendnp3/cpp/lib/CMakeLists.txt`, `cli/CMakeLists.txt` | Workspace targets, library options and dependencies, library sources and links, and CLI/CTest registration. Key options are `DNP3_DIAGNOSTIC_CLI`, `DNP3_TESTS`, `DNP3_TLS`, `DNP3_SA_CRYPTO` and `DNP3_FUZZING`. TLS and SA crypto are separate options. |
| `opendnp3/cpp/examples/`, `opendnp3/java/`, `opendnp3/dotnet/` | Optional upstream examples and bindings. |

## Core protocol and application

| Area | Open these files |
| --- | --- |
| Stack assembly | `src/DNP3Manager.cpp` → `src/DNP3ManagerImpl.cpp` → `src/channel/DNP3Channel.cpp` → `src/master/MasterStack.cpp` or `src/outstation/OutstationStack.cpp`. Public entry points are `api/DNP3Manager.h`, `api/channel/IChannel.h` and `api/IStack.h`. |
| Link and transport | `src/link/LinkContext.cpp`, `src/link/LinkLayerParser.cpp` and `api/link/LinkConfig.h` for frame parsing, addressing and link state. `src/transport/TransportStack.cpp`, `src/transport/TransportLayer.cpp`, `src/transport/TransportRx.cpp` and `src/transport/TransportTx.cpp` for layer wiring, reassembly and segmentation. |
| APDUs and objects | `src/app/parsing/APDUParser.cpp` gates qualifiers and dispatches to `src/app/parsing/CountParser.cpp`, `src/app/parsing/CountIndexParser.cpp`, `src/app/parsing/RangeParser.cpp` and `src/app/parsing/FreeFormatParser.cpp`. `src/app/HeaderWriter.cpp` is the shared write path. G51 CTO uses qualifier 07 and count 1. |
| Master | `src/master/MasterContext.cpp`, `src/master/MasterTasks.cpp` and `api/master/MasterStackConfig.h` for polling, scheduling, response ownership and timeouts. `src/master/MeasurementHandler.cpp` delivers typed values, header metadata and security association IDs to `api/master/ISOEHandler.h`. |
| Outstation | `src/outstation/OutstationContext.cpp`, `src/outstation/ReadHandler.cpp`, `src/outstation/WriteHandler.cpp`, `src/outstation/AssignClassHandler.cpp` and `src/outstation/FreezeRequestHandler.h` for request dispatch, class/freeze operations, responses, unsolicited reporting and application confirms. |
| Database and events | `src/outstation/Database.cpp`, `src/outstation/UpdateBuilder.cpp`, `api/outstation/DatabaseConfig.h` and `api/outstation/EventBufferConfig.h` for point updates, static reads and capacity. `src/outstation/event/EventBuffer.cpp`, `src/outstation/event/EventStorage.cpp`, `src/outstation/event/EventSelection.cpp` and `src/outstation/event/EventWriting.cpp` for bounded buffering, class/default variation selection and event serialization. |
| Controls | `src/master/CommandSet.cpp`, `src/master/CommandSetOps.cpp`, `src/master/CommandTask.cpp` and `src/master/TypedCommandHeader.h` for G12/G41 request building and echo/result handling. `src/outstation/CommandResponseHandler.h`, `src/outstation/CommandActionAdapter.h`, `src/outstation/ControlState.h` and `src/outstation/RequestHistory.cpp` for select/operate state, retry identity and dispatch to `api/outstation/ICommandHandler.h`. |
| Clock, IIN and restart | `src/master/SerialTimeSyncTask.cpp` and `src/master/LANTimeSyncTask.cpp` implement NonLAN and LAN paths. `src/outstation/TimeSyncState.h`, `src/outstation/WriteHandler.cpp` and `api/outstation/IOutstationApplication.h` are the Outstation hooks. G80V1 NEED_TIME clear delegates to the application, with a default implementation in `src/outstation/DefaultOutstationApplication.cpp`. The CLI uses NonLAN. |
| Object generation | `opendnp3/generation/pom.xml` is the Maven entry. Start with `groups/Group0.scala`, `groups/Group12.scala`, `groups/Group41.scala`, `groups/Group120.scala`, `groups/Group121.scala` or `groups/Group122.scala`. They register in `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/ObjectGroup.scala`. Shared renderers live in `opendnp3/generation/render/`. Generated outputs are `src/gen/objects/` and `api/gen/`. |

## Secure Authentication, attributes and platform boundaries

| Area | Open these files |
| --- | --- |
| G120 challenge/reply and sessions | `src/master/MasterResponder.cpp`, `src/outstation/OutstationChallenger.cpp`, `src/auth/AuthenticationSession.cpp`, `src/auth/SessionKeys.cpp` and `src/auth/AuthenticationMAC.h`. Required SA is the default in `api/auth/AuthenticationConfig.h` and fails closed when prerequisites are absent. Legacy compatibility requires explicit selection. |
| Aggressive mode and remote keys | `src/auth/AggressiveMode.cpp` for V3/V9 envelopes, replay and separate challenge histories. `src/auth/RemoteUpdateKeys.cpp`, `src/auth/UpdateKeyFunctions.cpp`, `src/master/UpdateKeyTask.cpp` and `api/auth/UpdateKeyConfig.h` for opt-in Methods 4/68, authority boundaries and durable user lifecycle. |
| G121/G122 | `src/auth/AuthenticationStatistics.cpp` tracks per-association counters, reporting baselines and protocol maxima. G121 READ/Class 0 snapshots flow through the database. `src/outstation/SecurityStatEventPublisher.cpp` publishes G122 occurrences into the event buffer. The Master uses typed delivery. See `api/outstation/OutstationConfig.h` and `api/auth/SecurityStatistic.h` for configuration and the retention interface. |
| G0 attributes | `src/app/parsing/DeviceAttributeParser.cpp`, `src/app/HeaderWriter.cpp`, `api/app/DeviceAttribute.h` and `src/outstation/DeviceAttributeSelection.cpp`. Outstation serves V210 and V254/V255 discovery. Master decodes V209/V210. Attribute-set index and SA association ID are separate fields. |
| TCP, UDP, serial and TLS | `src/channel/IOHandler.cpp` and `src/channel/` for I/O and reconnect. `src/channel/tls/SSLContext.cpp`, `src/channel/tls/TLSClient.cpp`, `src/channel/tls/TLSServer.cpp` and `api/channel/TLSConfig.h` for peer verification, optional exact SAN matching and separate TLS 1.2 cipher and TLS 1.3 suite settings. TCP/TLS listener ports are exposed through `api/channel/IChannel.h`. |
| Crypto and credentials | `src/crypto/CryptoProvider.h`, `src/crypto/OpenSSLCryptoProvider.cpp` and `src/crypto/README.md` for SA primitives. `src/auth/WindowsAuthenticationCredentials.cpp` and `api/auth/WindowsAuthenticationCredentials.h` for Windows Credential Manager, expiry and the remote-user journal. `cli/Security.cpp` and `cli/TestTLS.cpp` also contain **test-only** provisioning and short-lived authority/TLS fixtures. |
| STM32H743/FreeRTOS | No target implementation was identified in the tracked layout. Port boundaries are `src/DNP3ManagerImpl.cpp` and `src/channel/IAsyncChannel.h` for ASIO, executor/timers and I/O, the crypto and credential interfaces above for RNG/storage/trusted time, and the Outstation application and command interfaces for physical I/O, interlocks and restart. Dependency declarations are `opendnp3/deps/asio.cmake`, `opendnp3/deps/exe4cpp.cmake` and `opendnp3/deps/ser4cpp.cmake`. |

## Test entry points

- Catch/CTest targets are defined in `tests/unit/CMakeLists.txt`, `tests/integration/CMakeLists.txt` and `tests/asiotests/CMakeLists.txt`. Start parser and database investigations at `tests/unit/TestAPDUParsing.cpp` and `tests/unit/TestDatabase.cpp`. Reusable fixtures are in `tests/dnp3mocks/` and fuzz targets in `tests/fuzz/`.
- `cli/tests/ProcessSmoke.py` runs two local CLI processes through `pc-compat`, `pc-method4`, `pc-method68`, `pc-negative` and `pc-tls`. It selects a free port by binding and releasing a temporary socket before starting the peers. The native TCP/TLS fixtures have access to the actual listener port.
- `tests/integration/TestSecureAuthentication.cpp` covers native TCP SA, reconnect and restart. `tests/integration/TestEventIntegration.cpp` covers event flow. `tests/asiotests/TestTCPClientServer.cpp` is a socket fixture entry point.
- Local, untracked acceptance kit in this workspace: `DNP3-AUTOTEST-KIT/dnp3_acceptance.py`, `DNP3-AUTOTEST-KIT/TEST_CASES.json` and `DNP3-AUTOTEST-KIT/FREEBUFF_TEST_GUIDE.md`. The kit exercises local CLI/native binaries. Preserve its separate results directory as evidence.
- For independent interoperability, use the CLI as one endpoint with an external peer or Triangle MicroWorks Test Harness. The in-repo harnesses exercise local implementations. Consult the issue register for outstanding external validation.

## Unfinished or unsupported

- **SA and G0.** G120V8 is codec-only. Outstation G0V209 returns OBJECT_UNKNOWN and is omitted from discovery. Methods 4/68 are the implemented remote-key methods. V7 codes 5/7, SCS wrap and Method 68 DSA signature representation remain tracked as `P4-OPEN-01`, `RUK-OPEN-01` and `RUK-OPEN-02`.
- **Statistics.** The P1 sticky continuity fix is absent. G121 snapshot and G122 event flags depend on the initial retention load. A later save failure does not latch DISCONTINUITY. Durable target retention and per-point rearming remain open. Increment calls Publish before Persist, so a save failure cannot affect the flags of that same event. G122 explicit V2 does not supply a timestamp for an untimed historical event.
- **Level 4 and application behavior.** The supplied profile is Level 3 with extensions. Full Table 14-5 coverage remains open, including broader G0 and remaining command and measurement wire audits. G34 wire access and Outstation G13/G43 publication are implemented. The typed Master FC6 API completes on local transmission in Compatibility mode. REQUIRED mode rejects FC6. See `DNP3_PDD_PLAN/FC6_B3_REPORT.md` for local evidence and open interoperability work. The CLI simulates controls and has no remote hardware restart implementation.
- **Product security.** Cipher-change timeout, scheduled revocation, selected algorithms, RTU provisioning/roles and target hardening remain open. The TLS 1.3 suite list needs product clarification. See the security matrix and issue register for scope.

## Requirements and evidence

- `DNP3_PDD_PLAN/01_SOURCE_MAP.md` indexes the IEEE standard, Device Profile and security addendum. `DNP3_PDD_PLAN/IEEE_TRACEABILITY.csv`, `DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv` and `DNP3_PDD_PLAN/03_SECURITY_MATRIX.md` are requirement navigation.
- `DNP3_PDD_PLAN/README.md`, `DNP3_PDD_PLAN/05_PHASES_AND_CODEX.md`, `DNP3_PDD_PLAN/06_PREVIOUS_GUIDELINE_AUDIT.md` and `DNP3_PDD_PLAN/ISSUE_POSPONED1.md` cover planning, earlier audit and open decisions. `DNP3_PDD_PLAN/04_G0V209_CONTRACT.md` covers the attribute contract.
- `DNP3_PDD_PLAN/PROGRESS.md`, `DNP3_PDD_PLAN/PROGRESS_EVIDENCE.json` and `DNP3_PDD_PLAN/SECURITY_PROGRESS.csv` hold revision-scoped assessments and evidence. `scripts/progress.py` and `.github/workflows/progress.yml` maintain the dashboard in `README.md`.
- Focused reports are `DNP3_PDD_PLAN/DEVICE_PROFILE_MEASUREMENTS_REPORT.md`, `DNP3_PDD_PLAN/SA_REMOTE_UPDATE_KEYS_REPORT.md`, `DNP3_PDD_PLAN/P6b-M1_REPORT.md`, `DNP3_PDD_PLAN/P6b-O2_REPORT.md` and `DNP3_PDD_PLAN/P6c_REPORT.md`. Compare each report's tested revision and scenario to the task. Source support, local execution evidence and external conformance are separate.

## Task-to-file lookup

| Task | Start here |
| --- | --- |
| Object qualifier, CTO or typed delivery | `src/app/parsing/APDUParser.cpp`, `src/master/MeasurementHandler.cpp`, `tests/unit/TestProfileMeasurements.cpp` |
| READ, class assignment, event retry or CONFIRM | `src/outstation/OutstationContext.cpp`, `src/outstation/event/EventSelection.cpp`, `tests/unit/TestProfileClasses.cpp`, `tests/unit/TestOutstationEventResponses.cpp` |
| SBO, command echo or duplicate execution | `src/master/CommandTask.cpp`, `src/outstation/ControlState.h`, `src/outstation/RequestHistory.cpp`, `tests/unit/TestProfileControls.cpp` |
| Absolute time, LAN sync or IIN clear | `src/master/LANTimeSyncTask.cpp`, `src/outstation/WriteHandler.cpp`, `tests/unit/TestProfileTime.cpp` |
| SA handshake, renewals or restart | `src/auth/SessionKeys.cpp`, `tests/unit/TestProductionAuthentication.cpp`, `tests/integration/TestSecureAuthentication.cpp` |
| Remote Update Key and credential persistence | `src/auth/RemoteUpdateKeys.cpp`, `src/auth/WindowsAuthenticationCredentials.cpp`, `tests/unit/TestRemoteUpdateKeys.cpp` |
| G121/G122 counters, events or retention | `src/auth/AuthenticationStatistics.cpp`, `src/outstation/SecurityStatEventPublisher.cpp`, `tests/unit/TestAuthenticationStatistics.cpp`, `tests/unit/TestSecurityStatRead.cpp`, `tests/unit/TestSecurityStatEvents.cpp`, `tests/unit/TestMasterSecurityStatistics.cpp` |
| G0 version, count or discovery | `src/outstation/DeviceAttributeSelection.cpp`, `src/app/parsing/DeviceAttributeParser.cpp`, `tests/unit/TestDeviceAttributes.cpp` |
| TLS trust, listener ownership or process flake | `src/channel/tls/SSLContext.cpp`, `src/DNP3ManagerImpl.cpp`, `cli/Security.cpp`, `cli/tests/ProcessSmoke.py` |

## Discovery exclusions

Skip .git, .freebuff, build trees, caches, temporary files, binaries and DNP3-AUTOTEST-RESULTS during ordinary source discovery. Use the generator models before inspecting generated C++. Open the IEEE 1815 reference directory only for an assigned requirements check, using the page index above.
