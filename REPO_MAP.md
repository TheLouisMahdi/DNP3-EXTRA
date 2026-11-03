# Repository Map

C++ DNP3 workspace: two console apps + local OpenDNP3 3.1.2 source.
Paths are relative to this root; section prefixes apply where stated.
Read this map first; open only relevant files. Update after structural changes.
The workspace root is the current Git repository; `opendnp3/` is its library subtree.

## Entry Points
- `apps/master/main.cpp` → TCP client, polls, commands, measurement callbacks.
- `apps/outstation/main.cpp` → TCP server, point configuration, simulated updates.
- `opendnp3/cpp/lib/src/DNP3Manager.cpp` → library startup and channel creation.

## Core
Prefix: `opendnp3/cpp/lib/src/`
- `master/` → polling, command tasks, scheduling; start at `MasterContext.cpp`.
- `master/MeasurementHandler.*` → typed SOE delivery, including G121/G122 through shared RangeParser/CountIndexParser and the source-compatible SecurityStat callback. Raw index/Association ID are preserved; G122V2 accuracy is conservatively unknown/UNSYNCHRONIZED.
- `outstation/` → request handling, responses, unsolicited reporting; start at `OutstationContext.cpp`.
- `outstation/ReadHandler.h`, `outstation/WriteHandler.h` → object request dispatch.
- `outstation/Database.cpp` → in-memory point selection, updates, static responses.
- `outstation/event/` → event buffering and response serialization.
- `outstation/UpdateBuilder.cpp` → application measurement update batches.
- `app/` → APDU construction, object headers, measurement serialization.
- `app/parsing/APDUParser.cpp` → object/qualifier parsing and handler dispatch.
- `crypto/CryptoProvider.h` → shared internal cryptographic buffer interface.
- `crypto/OpenSSLCryptoProvider.cpp` → optional OpenSSL SA primitives; see `crypto/README.md`.
- `auth/SessionKeys.*`, `auth/AuthenticationSession.*` → bounded session-key lifecycle and authorization boundary.
- `auth/AuthenticationStatistics.*` → bounded association security counters, reporting baselines and five protocol maxima; frozen G121 READ snapshots and synchronous G122 occurrence notifications; reporting thresholds remain separate from protocol maxima.
- G121 continuity limitation: without a successful initial retention load, snapshots conservatively retain DISCONTINUITY. Per-point acquisition/transmission rearming is not implemented; a platform retention backend is still required for restart persistence. Normal UINT32 rollover does not set DISCONTINUITY.
- `outstation/SecurityStatEventPublisher.*` → copies G122 occurrence snapshots into the native bounded event buffer, using application DNP time and Class 1/2/3 configuration. Usable absolute occurrence time may be synchronized or unsynchronized; unavailable time produces V1 snapshots. Explicit V2 selection retains the untimed prefix without substitution or re-timestamping; application-owned NEED_TIME is preserved.
- `auth/AggressiveMode.*` → authenticated V3/V9 envelopes, separate solicited/unsolicited challenge histories and replay checks.
- `auth/WindowsAuthenticationCredentials.cpp` → read-only Windows Credential Manager adapter.
- `master/MasterResponder.*`, `outstation/OutstationChallenger.*` → Control/Monitoring challenge-response cores.
- `transport/` → fragment segmentation/reassembly.
- `link/` → frames, CRC, link state; start at `LinkContext.cpp`.
- `decoder/`, `logging/`, `util/` → diagnostics and shared helpers.

## Interfaces and Configuration
Prefix: `opendnp3/cpp/lib/include/opendnp3/`
- `DNP3Manager.h`, `channel/IChannel.h` → public manager/channel API.
- `master/` → master API/callbacks; `MasterStackConfig.h` configures the stack, `ISOEHandler.h` receives measurements.
- `outstation/` → outstation API/callbacks; `OutstationStackConfig.h`, `DatabaseConfig.h`, `EventBufferConfig.h` configure points/events.
- `outstation/ICommandHandler.h`, `outstation/IOutstationApplication.h` → control/application integration hooks.
- `outstation/UpdateBuilder.h` → measurement update API.
- `channel/`, `link/LinkConfig.h` → endpoint, serial, TLS, retry and addressing settings.
- `auth/AuthenticationConfig.h` → explicit secure/compatibility modes, users, credential retrieval and APDU authorization.
- `auth/SecurityStatistic.h` → IEEE indexes/default thresholds and portable durable-retention interface.
- `auth/WindowsAuthenticationCredentials.h` → Windows credential format and expiry contract.
- `app/` → public measurement and command types.

Runtime endpoints and stack settings live in the two app entry points.
The outstation database is in memory; the apps simulate measurements and accept controls without a custom hardware adapter.

## Network / Device I/O
- `opendnp3/cpp/lib/src/channel/DNP3Channel.cpp` → channel-to-stack assembly.
- `opendnp3/cpp/lib/src/channel/` → TCP, UDP, serial I/O handlers.
- `opendnp3/cpp/lib/src/channel/tls/` → optional OpenSSL transport.

## Tests
Prefix: `opendnp3/cpp/tests/`
- `unit/` → protocol/state tests; `TestAPDUParsing.cpp`, `TestDatabase.cpp` are parser/database starting points.
- `unit/TestMasterSecurityStatistics.cpp` → Master G121/G122 qualifiers, typed callbacks, association isolation, occurrence time, malformed fragments, native solicited/unsolicited paths and mixed-WRITE rejection protection.
- `unit/TestSecurityStatEvents.cpp` → G122 codecs, reporting, READ selection, event classes, native responses/CONFIRMs/retries, fragmentation and secure-context accounting hooks.
- `dnp3mocks/` → shared mocks and stack fixtures.
- `asiotests/` → asynchronous I/O tests.
- `integration/` → stack integration tests.
- `fuzz/` → parser fuzz targets.
Enable C++ tests with `DNP3_TESTS`; fuzz targets use `DNP3_FUZZING`.
`DNP3_SA_CRYPTO` enables SA cryptographic and runtime components independently of TLS.
Stacks require credentials and an authorization policy by default; legacy operation must explicitly
select `AuthenticationConfig::Mode::COMPATIBILITY`. Required SA fails closed when crypto or credentials
are unavailable. Challenge-response and session-key exchange are integrated; full SA v5 capabilities
remain in progress and are not advertised. `integration/TestSecureAuthentication.cpp` (`[sa-tcp]`)
verifies real local TCP READ/CONTROL, count renewal, reconnect and Outstation restart with ephemeral keys.

## Build and Optional Components
- `CMakeLists.txt` → builds local library, `master`, `outstation`.
- `opendnp3/CMakeLists.txt` → library version, optional tests/examples/TLS/bindings, CPack packaging.
- `opendnp3/cpp/lib/CMakeLists.txt` → library source list, linking, installation.
- `opendnp3/deps/*.cmake` → dependency acquisition declarations; inspect only for dependency/build work.
- `opendnp3/cmake/` → formatting, linting, coverage helpers.
- `opendnp3/.github/workflows/ci.yml` → upstream build/test/package workflow.
- `opendnp3/cpp/examples/` → optional reference apps; separate from workspace apps.
- `opendnp3/java/`, `opendnp3/dotnet/` → optional language bindings and their builds.
- `opendnp3/generation/` → Maven/Scala code generators; protocol models under `dnp3/src/main/scala/com/automatak/render/dnp3/`, shared renderers under `render/`.

## Requirements Navigation
- `DNP3_PDD_PLAN/README.md` → planning scope and reading order.
- `DNP3_PDD_PLAN/01_SOURCE_MAP.md` → standards/profile PDF page index, not a code index.
- `DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv` → requested object/variation matrix.
- `DNP3_PDD_PLAN/03_SECURITY_MATRIX.md` → security requirements.
- `DNP3_PDD_PLAN/04_G0V209_CONTRACT.md` → first device-attribute contract.
- `DNP3_PDD_PLAN/05_PHASES_AND_CODEX.md` → implementation sequence.
Planning documents describe requirements, not verified implementation support.

## Dependency Flow
- Build: root CMake → OpenDNP3 library → both console apps link it.
- Startup: app → DNP3Manager → channel → master/outstation stack.
- Protocol: master/outstation ↔ app encoding/parsing ↔ transport ↔ link ↔ channel I/O.
- Measurements: outstation app → UpdateBuilder → Database/event buffer → responses → master ISOEHandler.
- Generation: Scala models/renderers → generated C++ enums/objects.

## Ignore During Discovery
- `build/`, `**/build/`, `dist/`, `target/`, `bin/`, `obj/`, `_deps/` → outputs/dependencies.
- `.git/`, `.freebuff/`, caches, virtual environments, logs, temporary files, binaries.
- `opendnp3/cpp/lib/src/gen/`, `opendnp3/cpp/lib/include/opendnp3/gen/` → generated; use generator sources first.
- `IEEE 1815/` → reference PDFs; consult planning page index only when standards work requires them.
- `steps/` → currently empty.
