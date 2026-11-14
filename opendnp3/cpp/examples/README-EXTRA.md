# DNP3-EXTRA C++ TCP examples

These are **interactive examples**, not production RTU configurations or conformance tests.
They explicitly use `AuthenticationConfig::Mode::COMPATIBILITY`, print **SA DISABLED**,
and bind the Outstation to loopback only. For SA v5, TLS, roles and protected controls,
use `dnp3-cli` and the established acceptance runner.

## Build in PowerShell 7

From the DNP3-EXTRA repository root, using the existing compatible toolchain:

```powershell
$ErrorActionPreference = 'Stop'
cmake -S opendnp3 -B build/native -DDNP3_EXAMPLES=ON
if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
cmake --build build/native --config Release --target master-demo outstation-demo --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Example build failed' }
```

Launch in separate PowerShell terminals (paths are relative to the repository root):

```powershell
& .\build\native\cpp\examples\outstation\Release\outstation-demo.exe --port 20000
```

```powershell
& .\build\native\cpp\examples\master\Release\master-demo.exe --port 20000
```

### Outstation commands

```text
set binary 0 on suppress
set double 0 intermediate suppress
set analog 0 12.5 suppress
set bos 0 on suppress
set aos 0 -3.5 suppress
set analog 0 13.5 force
```

`bos` and `aos` inject **simulated output-status measurements**, not physical
control operation. `force` requests an event and `suppress` suppresses it.
All injected measurements use ONLINE flags and the current example clock.
The old one-letter commands still work.

### Master commands

`s <group> <variation> <qualifier> [start stop]` sends an actual FC1 READ.
Qualifier values are decimal: 6 = Q06 all objects, 0 = Q00 (8-bit range),
1 = Q01 (16-bit range). For example:

```text
s 1 1 6
s 3 2 6
s 30 5 0 0 0
s 30 5 1 0 0
s 30 5 6
s 10 2 6
s 40 3 6
```

The Master prints asynchronously received values via `PrintingSOEHandler`.
`READ queued` means only that the request was submitted. Check the actual
received index/value/quality and error messages. The demo's default G32 event
variation for analog point 0 is G32V5.

## Focused real-TCP process test

```powershell
$ErrorActionPreference = 'Stop'
py -3 -B opendnp3/cpp/examples/tests/ExampleProcessSmoke.py `
    --master build/native/cpp/examples/master/Release/master-demo.exe `
    --outstation build/native/cpp/examples/outstation/Release/outstation-demo.exe
if ($LASTEXITCODE -ne 0) { throw 'Example TCP smoke test failed' }
```

This test starts two separate processes on a temporary loopback port, checks
selected G1/G3/G10/G30/G40 READ responses and invalid command inputs, then
shuts both processes down. It does **not** prove exact wire encoding or SA v5.
Use existing `pc-profile-binary-wire`, `pc-profile-analog-wire`,
`pc-profile-g41-wire` and requirement-specific acceptance cases for those gates.
Record Windows execution and tested SHA before claiming verification.
