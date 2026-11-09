#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$List,
    [switch]$All,
    [string[]]$Requirement,
    [string]$Scenario,
    [string]$Vector,
    [switch]$ContinueOnFailure,
    [uint32]$Seed = 1741815,
    [string]$Config,
    [string]$ArtifactRoot,
    [string]$BuildReceipt,
    [string]$Python
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
# A desktop parent process may predate the persistent user dependency setting.
if (-not $env:VCPKG_ROOT) {
    $env:VCPKG_ROOT = [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'User')
}
$runner = Join-Path $PSScriptRoot 'RunDnp3Acceptance.py'
$pythonPrefix = @()
if ($Python) {
    $pythonExe = (Get-Command -Name $Python -CommandType Application).Source
} elseif (Get-Command py -CommandType Application -ErrorAction SilentlyContinue) {
    $pythonExe = (Get-Command py -CommandType Application | Select-Object -First 1).Source
    $pythonPrefix = @('-3')
} elseif (Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue) {
    $pythonExe = (Get-Command python3 -CommandType Application).Source
} else {
    $pythonExe = (Get-Command python -CommandType Application).Source
}
$runnerArgs = @('-B', $runner, '--seed', "$Seed")
if ($Build) { $runnerArgs += '--build' }
if ($List) { $runnerArgs += '--list' }
if ($All) { $runnerArgs += '--all' }
foreach ($id in $Requirement) { $runnerArgs += @('--requirement', $id) }
if ($Scenario) { $runnerArgs += @('--scenario', $Scenario) }
if ($Vector) { $runnerArgs += @('--vector', $Vector) }
if ($ContinueOnFailure) { $runnerArgs += '--continue-on-failure' }
if ($Config) { $runnerArgs += @('--config', $Config) }
if ($ArtifactRoot) { $runnerArgs += @('--artifact-root', $ArtifactRoot) }
if ($BuildReceipt) { $runnerArgs += @('--build-receipt', $BuildReceipt) }
& $pythonExe @pythonPrefix @runnerArgs
exit $LASTEXITCODE
