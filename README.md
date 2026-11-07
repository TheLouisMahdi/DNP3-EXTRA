# DNP3-EXTRA

OpenDNP3 3.1.2 extensions with native Master and Outstation APIs, TCP/UDP/serial channels, Secure Authentication components and a Windows TCP/mutual-TLS diagnostic CLI.

## Scope
The supplied 12-page RTU Device Profile selects a Level 3 Outstation with explicit extensions. Acceptance covers its 69 object/function rows, runtime settings on pages 1–4 and the 36 security addendum rows. IEEE 1815-2012 governs the selected protocol behavior. Master responsibilities follow the selected functionality and explicit project requirements. [Scope and acceptance](DNP3_PDD_PLAN/PDF_SCOPE.md)

Implemented paths include measurement/events, controls, time synchronization, G34 deadbands, G13/G43 command events, typed Master FC6 in Compatibility mode, authenticated FC6 (B03, verified in selected Windows Host tests on 2026-11-07), SA challenge/reply and Aggressive exchanges, remote update-key Methods 4/68, G121/G122 and mutual TLS diagnostics. Completion remains subject to per-requirement evidence.

Open requirements include truthful G0V209 capability reporting, runtime G120V8, authenticated FC6 independent-peer verification, product crypto selections, retention and physical RTU security/integration. The CLI operates simulated I/O. [Open issues](DNP3_PDD_PLAN/OPEN_ISSUES.md)

## Build and test
Use installed compatible CMake, MSVC, Python 3 and OpenSSL 3 dependencies. Reuse the existing toolchain/cache configuration when available. CMake fetches pinned ASIO/executor/serialization dependencies. Commands below build the native library and diagnostic tests from the repository root.

```powershell
cmake -S opendnp3 -B build/native -DDNP3_DIAGNOSTIC_CLI=ON -DDNP3_SA_CRYPTO=ON -DDNP3_TLS=ON -DDNP3_TESTS=ON
cmake --build build/native --config Release --target dnp3-cli unittests integrationtests asiotests --parallel 4
ctest --test-dir build/native -C Release --output-on-failure
# Focused typed FC6 tests
& ./build/native/cpp/tests/unit/Release/unittests.exe '[fc6-master]'
```

The workspace CMakeLists.txt additionally defines the `master` and `outstation` demos under `apps/`. Object generation uses the existing Maven/Scala project under `opendnp3/generation/`. [Detailed Windows build, provisioning and tests](cli/README.md)

## Run
Launch the following in separate PowerShell terminals.

```powershell
& ./build/native/cli/Release/dnp3-cli.exe outstation
& ./build/native/cli/Release/dnp3-cli.exe master
```

These diagnostic defaults use explicit unprotected Compatibility mode on localhost port 20000. For SA test provisioning, role tests and TLS on port 19999, follow the CLI guide. Production credentials and RTU deployment require the selected security controls. [CLI operations](cli/README.md)

## Requirements and evidence
- [Profile matrix](DNP3_PDD_PLAN/PROFILE_MATRIX.csv) retains all 69 original IDs and recorded evidence.
- [Security matrix](DNP3_PDD_PLAN/SECURITY_MATRIX.csv) retains all 36 IDs, source requirements, classifications and historical evidence.
- [Engineering evidence](DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md) preserves tested revisions and limitations. Historical records require review against current source.
- [Repository map](REPO_MAP.md) provides direct implementation and test paths.

Independent interoperability and physical STM32H743/FreeRTOS validation remain separate acceptance obligations. No certification is claimed.
