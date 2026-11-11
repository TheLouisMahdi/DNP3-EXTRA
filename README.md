# DNP3-EXTRA

OpenDNP3 3.1.2 extensions with native Master and Outstation APIs, TCP/UDP/serial channels, Secure Authentication and a Windows TCP/mutual-TLS diagnostic CLI. The CLI simulates RTU I/O.

## Requirements

The [canonical workbook](DNP3_PDD_PLAN/DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx) holds the 119 selected requirements, exact wire procedures, decisions, implementation status and verification evidence. The Device Profile selects a Level 3 Outstation with explicit extensions and the security addendum selects SA v5. IEEE 1815-2012 governs the selected protocol behavior. The workbook's SOURCES sheet identifies the original documents and their page anchors.

Filter IMPLEMENTATION_INDEX by ID, then follow WIRE_PROCEDURES and OPEN_DECISIONS. Record evidence at the tested revision. Host, independent-peer and STM32H743/FreeRTOS acceptance have separate evidence requirements. Group 70 and general Level 4 expansion are outside the 119 selections.

## Build and test

Use compatible CMake, MSVC, Python 3 and OpenSSL 3 installations. Reuse the existing toolchain and build cache. CMake uses pinned ASIO, executor and serialization dependencies. From the repository root with OpenSSL discoverable:

~~~powershell
cmake -S opendnp3 -B build/native -DDNP3_DIAGNOSTIC_CLI=ON -DDNP3_SA_CRYPTO=ON -DDNP3_TLS=ON -DDNP3_TESTS=ON
cmake --build build/native --config Release --target dnp3-cli unittests integrationtests asiotests --parallel 4
ctest --test-dir build/native -C Release --output-on-failure
~~~

Use the [CLI guide](cli/README.md) for the existing Windows/vcpkg setup, simulated peers, test credential provisioning and mutual TLS. Use the [acceptance runbook](tools/ACCEPTANCE-RUNBOOK.md) for focused Host scenarios and evidence collection.

[Engineering instructions](AGENTS.md) · [Repository map](REPO_MAP.md)
