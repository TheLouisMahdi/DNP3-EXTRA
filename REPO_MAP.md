# Repository map

Scope and acceptance live in `DNP3_PDD_PLAN/PDF_SCOPE.md`. The workspace root is the Git repository. OpenDNP3 3.1.2 is under `opendnp3/`.

Path shorthand below is exact. `src/` means `opendnp3/cpp/lib/src/`, `api/` means `opendnp3/cpp/lib/include/opendnp3/`, `tests/` means `opendnp3/cpp/tests/`, and `groups/` means `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/`.

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
- Reusable acceptance manifest and guide, with an unverified local runner: `DNP3-AUTOTEST-KIT/dnp3_acceptance.py`, `DNP3-AUTOTEST-KIT/TEST_CASES.json` and `DNP3-AUTOTEST-KIT/FREEBUFF_TEST_GUIDE.md`. The kit exercises local CLI/native binaries. Preserve its separate results directory as evidence.
- For independent interoperability, use the CLI as one endpoint with an external peer or Triangle MicroWorks Test Harness. The in-repo harnesses exercise local implementations. Consult the issue register for outstanding external validation.


## Dependencies and focused navigation

- CMake entry points above register existing source/test targets. `opendnp3/deps/asio.cmake`, `exe4cpp.cmake` and `ser4cpp.cmake` pin runtime dependencies. TLS and SA crypto use OpenSSL. Maven and the pinned Scala dependencies in `opendnp3/generation/pom.xml` own generation.
- Follow one feature through its Scala model, generated object/enum, shared APDU parser/writer, role handler and permanent tests. Search only within those modules.
- `DNP3_PDD_PLAN/PROFILE_MATRIX.csv` holds 69 Profile IDs. `SECURITY_MATRIX.csv` holds 36 security IDs and source summaries. `OPEN_ISSUES.md` tracks decisions and target blockers.
- `ENGINEERING_EVIDENCE.md` preserves historical reports, interpretation details and tested revisions. `PROGRESS_EVIDENCE.json` retains the original execution snapshot. `IEEE_TRACEABILITY.csv` retains 712 reference-only rows with unique IEEE/source references.
- `cli/README.md` provides detailed diagnostic commands and historical Windows execution evidence. The local `DNP3-AUTOTEST-KIT/dnp3_acceptance.py` is excluded from accepted evidence.
- Skip build trees, `.git/`, caches and local test results during ordinary source discovery. Consult only the relevant pages of the supplied PDFs when resolving requirements.
