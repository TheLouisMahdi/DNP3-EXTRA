# DNP3-EXTRA automated acceptance

The catalog has 448 scenarios across 54 requirements. See [coverage](../opendnp3/cpp/tests/acceptance/COVERAGE.md) for executable bindings, pending Host scenarios and external gates. Campaign results describe the tested source and binaries. Contractual statuses remain in the project coverage records.

## Install once

Use PowerShell 7 and a clean repository without Phase 0 installed. Save `DNP3-54-AUTOMATED-ACCEPTANCE.patch` directly on the Desktop. This procedure resolves redirected Desktop locations through Windows.

```powershell
$ErrorActionPreference = 'Stop'
$desktop = [Environment]::GetFolderPath('Desktop')
$repo = Join-Path $desktop 'DNP3-EXTRA'
$patch = Join-Path $desktop 'DNP3-54-AUTOMATED-ACCEPTANCE.patch'

if (-not (Test-Path -LiteralPath $repo -PathType Container)) { throw "Repository not found: $repo" }
if (-not (Test-Path -LiteralPath $patch -PathType Leaf)) { throw "Patch not found: $patch" }

Set-Location -LiteralPath $repo
$expected = '64f6f932ed9f386a81275bcc65119ceb708d5b05'
$head = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot read repository HEAD.' }
$actual = ($head | Out-String).Trim()
if ($actual -ne $expected) { throw "Repository HEAD mismatch: $actual" }
$changes = @(& git status --porcelain=v1)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) { throw 'Working tree is not clean. No changes applied.' }

git apply --check --whitespace=error $patch
if ($LASTEXITCODE -ne 0) { throw 'Patch validation failed.' }
git apply --whitespace=error $patch
if ($LASTEXITCODE -ne 0) { throw 'Patch application failed.' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'Applied patch has whitespace errors.' }
Write-Host 'Unified acceptance patch applied successfully.'
```

## Run from the repository root

Use Git, Python 3.9+, CMake on PATH, Visual Studio with the C++ workload and discoverable OpenSSL 3. The default generator is Visual Studio 17 2022, x64, Release. A first configure may need network access for dependencies pinned by the existing project. The PowerShell entry point searches for `py -3`, `python3` and `python` in that order. Use `-Python` to specify an installed executable. For vcpkg, set `VCPKG_ROOT` to the installed root or specify a toolchain in `-Config` using [the example](dnp3-acceptance.example.json).

On this Windows workstation, the complete installation is at `%LOCALAPPDATA%\DNP3Tools\vcpkg`, with `openssl:x64-windows` 3.6.5#2. The separate `%LOCALAPPDATA%\vcpkg` directory contains cached archives only and must not be used as a toolchain root. The user-level `VCPKG_ROOT` setting points to the complete installation. The PowerShell entry point reads that persistent setting when the process environment has no `VCPKG_ROOT`, including terminals launched by a desktop application that predates the setting. No PowerShell profile or manual session variables are required. An explicit process `VCPKG_ROOT` or configured toolchain still takes precedence.

```powershell
.\tools\run-acceptance.ps1 -All -ContinueOnFailure
$campaignExitCode = $LASTEXITCODE
```

A selection containing a bound case automatically configures and builds the native targets. The script prints the evidence and summary paths, including when there is a test or setup failure. `-BuildReceipt` reuses a previous build only when source identity, configuration and executable hashes match. Use `-Build` alone for a build without scenario execution.

```powershell
.\tools\run-acceptance.ps1 -List
.\tools\run-acceptance.ps1 -Requirement PROFILE-003
.\tools\run-acceptance.ps1 -Scenario AT-PROFILE-003-RD00
.\tools\run-acceptance.ps1 -Scenario AT-PROFILE-003-RD00 -Vector V2 -Seed 1741815
py -3 -B -m unittest discover -s tools/tests -p test_acceptance_infra.py -v
```

`-List` performs discovery only. Omit `-ContinueOnFailure` for fail-fast. Current native vectors use fixed stimuli and test clocks. Their reproduction records the seed and source identity. SA uses fresh cryptographic randomness and the TCP test uses ephemeral loopback ports. The oracle uses public outcomes independent of those values.

| Exit | Result |
| ---: | --- |
| 0 | Selected campaign passed or build-only succeeded |
| 1 | At least one selected scenario failed a structured oracle |
| 2 | Setup, infrastructure, timeout or inconclusive evidence |
| 3 | Selected Host coverage remains unimplemented or selected coverage is blocked |

## Evidence and extensions

The default evidence root is `DNP3-EXTRA-TEST-EVIDENCE` beside the checkout. Use `-ArtifactRoot` for another directory outside the repository. Each campaign allocates a new ID and seals its evidence inventory with SHA-256. Build and temporary process directories are siblings of run directories. A completed run has `summary.md`, `requirements.csv`, `scenarios.csv`, `junit.xml` and a result directory for each catalog row. An attempted vector includes `scenario.json`, a timeline, public wire and receiver observations, JUnit and a focused `failure.md` when applicable. The runner withholds raw stdout/stderr and persists byte counts and reviewed numeric observations. A crash or early assertion may prevent an observation from being emitted. The last confirmed event and the first missing check remain available in the timeline.

The CSV keeps the supplied scenario IDs, scope and planning status. `phase0.json` holds the executable routes and independent expected-result fixtures. A future binding requires a real native case or explicit process dispatch, an independent oracle for each selected vector and observed effects on the applicable receiver. Use `utils/AcceptanceObservation.h` for public wire, state or receiver checks. Never pass raw authentication payloads, credentials, keys, MACs or free-form child output to the observation channel. A zero child exit without complete matching observations yields INCONCLUSIVE. Hardware, policy and independent-peer gates stay separate from Host coverage.
