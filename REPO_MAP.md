# Repository Map

Git lives at the workspace root; `opendnp3/` contains OpenDNP3 3.1.2.
Scope: Level 3 Outstation, selected extensions and SA v5; see the selected reference below.

Path aliases: `src/` = `opendnp3/cpp/lib/src/`; `api/` = `opendnp3/cpp/lib/include/opendnp3/`; `tests/` = `opendnp3/cpp/tests/`.

## Entry Points

- `apps/master/main.cpp` → TCP Master demo; polls and controls.
- `apps/outstation/main.cpp` → TCP Outstation demo; simulated points.
- `cli/main.cpp` → diagnostic console; role selection, commands and callbacks.
- `cli/Security.cpp`, `cli/TestTLS.cpp` → test credential/authority and TLS provisioning.
- `cli/README.md` → build, provisioning and console commands.
- `opendnp3/cpp/examples/` → transport examples; `opendnp3/java/`, `opendnp3/dotnet/` → optional bindings.

## Core

- `src/DNP3Manager.cpp`, `src/DNP3ManagerImpl.cpp` → stack lifecycle and executor assembly.
- `src/master/MasterContext.cpp`, `src/master/MasterTasks.cpp` → task scheduling, responses and timeouts.
- `src/master/CommandTask.cpp`, `src/master/CommandSetOps.cpp` → G12/G41 control requests and results.
- `src/master/MeasurementHandler.cpp` → typed measurement delivery.
- `src/master/SerialTimeSyncTask.cpp`, `src/master/LANTimeSyncTask.cpp` → time synchronization.
- `src/outstation/OutstationContext.cpp` → request orchestration, responses and confirmations.
- `src/outstation/ReadHandler.cpp`, `WriteHandler.cpp`, `AssignClassHandler.cpp` → reads, writes and class assignment (same directory).
- `src/outstation/CommandResponseHandler.h`, `ControlState.h` → control dispatch and select/operate state (same directory).
- `src/outstation/Database.cpp`, `UpdateBuilder.cpp` → in-memory point storage and updates (same directory).
- `src/outstation/event/` → event buffering, selection and serialization.
- `src/outstation/DeviceAttributeSelection.cpp` → G0 attribute responses/discovery.
- `src/app/parsing/APDUParser.cpp`, `src/app/parsing/` → shared object/qualifier validation and dispatch.
- `src/app/HeaderWriter.cpp` → shared APDU serialization.
- `src/link/`, `src/transport/` → framing/link state and fragment segmentation/reassembly.

## Security

- `src/auth/AuthenticationSession.cpp`, `SessionKeys.cpp` → authentication/session-key lifecycle (same directory).
- `src/master/MasterResponder.cpp`, `src/outstation/OutstationChallenger.cpp` → SA challenge/reply role handling.
- `src/auth/AggressiveMode.cpp` → Aggressive envelopes and replay tracking.
- `src/auth/RemoteUpdateKeys.cpp`, `src/master/UpdateKeyTask.cpp` → remote key/user lifecycle.
- `src/auth/AuthenticationStatistics.cpp`, `src/outstation/SecurityStatEventPublisher.cpp` → G121 counters/G122 events.
- `src/crypto/` → crypto provider interfaces and OpenSSL implementation.
- `src/auth/WindowsAuthenticationCredentials.cpp` → Windows credential storage and user journal.

## Interfaces and Configuration

- `api/DNP3Manager.h`, `api/channel/IChannel.h` → public stack/channel creation.
- `api/master/MasterStackConfig.h`, `MasterParams.h` → Master settings (same directory).
- `api/master/ISOEHandler.h` → received measurement callback interface.
- `api/outstation/OutstationConfig.h`, `DatabaseConfig.h`, `EventBufferConfig.h` → runtime/point/event settings (same directory).
- `api/outstation/ICommandHandler.h`, `IOutstationApplication.h` → physical I/O, clock and restart hooks (same directory).
- `api/auth/AuthenticationConfig.h`, `UpdateKeyConfig.h` → SA policy and provisioning contracts (same directory).
- `api/channel/TLSConfig.h`, `api/link/LinkConfig.h` → TLS and link settings.
- `src/channel/`, `src/channel/tls/` → ASIO TCP/UDP/serial, reconnect and TLS verification.
- `src/channel/IAsyncChannel.h` → platform I/O boundary; STM32H743/FreeRTOS integration remains pending.

## Build and Generation

- `CMakeLists.txt` → workspace library, CLI and demo targets.
- `opendnp3/CMakeLists.txt` → library options; TLS, SA crypto, tests, bindings and examples.
- `opendnp3/cpp/lib/CMakeLists.txt` → library sources and linkage.
- `cli/CMakeLists.txt` → CLI target and process-test registration.
- `opendnp3/deps/` → pinned CMake dependency declarations.
- `opendnp3/generation/pom.xml` → Maven/Scala generator build.
- `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/` → authoritative object/enum models; `objects/groups/Group*.scala` selects wire objects.
- `opendnp3/generation/render/` → shared rendering machinery.
- `README.md` → build/test overview; deployment/physical RTU acceptance remains open.

## Tests

- `tests/unit/` → Catch protocol tests; start at `TestAPDUParsing.cpp`, `TestDatabase.cpp`.
- `tests/unit/TestProductionAuthentication.cpp`, `TestAuthenticationRuntime.cpp`, `TestRemoteUpdateKeys.cpp` → SA policy, exchanges and key lifecycle (same directory).
- `tests/unit/TestDeviceAttributes.cpp`, `TestSecurityStatRead.cpp`, `TestSecurityStatEvents.cpp` → G0/G121/G122 coverage (same directory).
- `tests/integration/` → stack/event/TCP SA integration; start at `TestSecureAuthentication.cpp`.
- `tests/asiotests/` → executor, socket and TLS tests.
- `tests/dnp3mocks/` → reusable fixtures; `tests/fuzz/` → parser fuzz targets.
- `cli/tests/ProcessSmoke.py` → process scenarios: compatibility, Methods 4/68, denial, renewal, reply timeout and TLS.
- `DNP3-AUTOTEST-KIT/TEST_CASES.json`, `FREEBUFF_TEST_GUIDE.md` → acceptance case index/guide (same directory).

## Requirements and Evidence

- `AGENTS.md` → engineering and verification rules.
- `DNP3_PDD_PLAN/DNP3_REFERENCE_119.csv` → first lookup for the 119 selected requirements, exact wire cases and evidence boundaries.
- `DNP3_PDD_PLAN/DNP3_REFERENCE_WIRE_PROCEDURES.csv` and `IEEE_REFERENCE_OPEN_DECISIONS.md` → linked procedures and engineering dispositions.
- `DNP3_PDD_PLAN/DNP3_REFERENCE_USAGE.md` → editable workbook and export workflow. Consult the cited PDF pages for unresolved source questions.
- `DNP3_PDD_PLAN/WINDOWS_HOST_ROADMAP.md` and `EXECUTION_PHASE_STATUS.md` → implementation and executed evidence at their recorded revisions.

## Dependency Flow

- Apps/CLI → public APIs → DNP3Manager → channel → MasterStack/OutstationStack → role contexts.
- Role contexts → shared APDU parser/writer → transport → link → channel I/O.
- Outstation handlers → database/event buffer → response serialization; controls → application hooks.
- Role SA components → authentication/key state → crypto/credential providers.
- Scala models → generators → generated codecs/enums → parser/role handlers → tests.

## Ignore During Source Navigation

Build trees (`build/`, `build-*/`, `cmake-build-*/`), fetched dependencies (`_deps/`), generated outputs (`src/gen/`, `api/gen/`), `target/`, `bin/`, `obj/`, `.git/`, IDE/cache folders, virtual environments, test results, fuzz corpus data, binaries, logs, temporary files and unrelated assets. Use Scala models when changing generated objects/enums.
