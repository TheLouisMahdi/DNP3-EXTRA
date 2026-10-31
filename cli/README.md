# DNP3-EXTRA Diagnostic CLI

Standalone, C++14 Master/Outstation console application using existing OpenDNP3 APIs.
It does not modify the protocol library, perform Secure Authentication, or control real outputs.

## Integrate

Copy this `cli/` directory to the **root** of `DNP3-EXTRA/` (alongside `apps/` and `opendnp3/`).
Append the following line to the **root** `CMakeLists.txt` (Codex may do this):

```cmake
add_subdirectory(cli)
```

Configure/build using the same MSVC x64 toolchain and CMake dependency setup as the repository, for example:

```powershell
cmake -S . -B build-cli -A x64
cmake --build build-cli --config Release --target dnp3-cli
```

Run these in separate terminals:

```powershell
.\build-cli\cli\Release\dnp3-cli.exe outstation
.\build-cli\cli\Release\dnp3-cli.exe master
```

Actual executable location can depend on CMake generator configuration.

## Commands

Master:

- `read 1 2 0 3` - request G1V2, indices 0-3
- `read 30 5 0 0` - request G30V5 index 0
- `scan integrity` or `scan class1`, `scan class2`, `scan class3`
- `crob 0 on` or `crob 0 off` - real Select-And-Operate APDU, simulated device response
- `status`, `trace on`, `trace off`, `help`, `quit`

Outstation:

- `set binary 0 on` or `set binary 0 off`
- `set double 0 on` or `set double 0 off`
- `set analog 0 12.5`
- `set counter 0 100`
- `show`, `status`, `trace on`, `trace off`, `help`, `quit`

Only index 0 accepts local `set` commands in this initial diagnostic CLI. The outstation database has additional configured points for existing sample behavior. `show` displays local sample state, not a remote/database readback. All other protocol paths use OpenDNP3.

## Diagnostic behavior

- Summary mode prints actual SOE measurement callbacks and control results.
- Trace mode enables the existing OpenDNP3 channel/stack protocol logs (including APDU/hex).
- `read` queues a real DNP3 request; the `[TX]` line indicates a request was submitted, **not** that the remote station accepted it.
- Control `SUCCESS` is simulated by the example Outstation `SimpleCommandHandler`; no physical output changes.
- Raw application logging from the OpenDNP3 library may interrupt interactive input; this app does not replace the terminal line editor.
- Secure Authentication v5 is **not active** in this CLI.
