# DNP3-EXTRA

OpenDNP3 3.1.2 extensions with native Master and Outstation APIs, TCP/UDP/serial channels, Secure Authentication components and a Windows TCP/mutual-TLS diagnostic CLI.

## Scope

The RTU Device Profile selects a Level 3 Outstation with explicit extensions. The project tracks 119 requirements across 69 Profile, 36 Security and 14 runtime configuration IDs. IEEE 1815-2012 governs the selected protocol behavior. Master obligations follow the selected functions and explicit project requirements. [Historical scope and acceptance criteria](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN/PDF_SCOPE.md)

The native paths cover measurements and events, controls, time synchronization, SA Challenge/Reply and Aggressive Mode, remote Update Key Methods 4/68, G121/G122 and mutual TLS diagnostics. The Windows CLI uses simulated I/O. Group 70 is a separately tracked extension. It includes V2–V8 codecs and opt-in authorized Outstation file metadata lookup. File transfer and the corresponding Master API remain open.

## Implementation progress

Reviewed source snapshot [`eb45756`](https://github.com/TheLouisMahdi/DNP3-EXTRA/commit/eb45756fb9b7f4e265091280067c8f9285fb1477).

| Core RTU Host milestone | Progress | Basis |
| --- | --- | --- |
| Source slices landed | `■■■■` **4/4** | Confirmed link, application timing and CONFIRM, event qualifiers, diagnostic CLI |
| Slices with matching Windows acceptance evidence recorded | `□□□□` **0/4** | Unified Windows acceptance is deferred for this source snapshot |
| Overall Host requirements | **Current consolidated audit pending** | 119 tracked IDs, including open and product-dependent subcases |

The bars count only the four Core RTU Host slices. See the [execution ledger](EXECUTION_PHASE_STATUS.md#core-rtu-host-implementation) for commits and remaining gates. [Previous dashboard](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/5754b7b3e4e2e157771dae2008601a0456adc2f6/DNP3_PDD_PLAN/PROGRESS.md)

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

- [Current execution ledger](EXECUTION_PHASE_STATUS.md) records code changes, outstanding decisions and deferred verification. [Windows acceptance case index](WINDOWS_TEST_TITLES.md) lists planned coverage.
- [Historical profile matrix](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN/PROFILE_MATRIX.csv) and [historical security matrix](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN/SECURITY_MATRIX.csv) preserve requirement IDs and prior assessments.
- [Historical engineering evidence](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md) records results for specific revisions, including the November 7, 2026 Windows Host tests for selected authenticated FC6 scenarios. These results apply to their recorded test scope and revision.
- [Historical open issues](https://github.com/TheLouisMahdi/DNP3-EXTRA/blob/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN/OPEN_ISSUES.md) and the [repository map](REPO_MAP.md) give background and source locations.

Open gates include G120V8 certificate trust and runtime handling, truthful G0V209 advertisement, security policy decisions, TLS revocation lifecycle and authenticated FC6 independent-peer verification. STM32H743/FreeRTOS integration and physical acceptance are tracked separately.
