param(
    [string]$Repo = 'D:\C drive\User\Desktop\DNP3-EXTRA'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-GitPaths([string]$Repository) {
    # NUL-separated UTF-8 output handles spaces and non-ASCII filenames.
    $start = [System.Diagnostics.ProcessStartInfo]::new('git')
    $start.WorkingDirectory = $Repository
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    foreach ($argument in @('ls-files', '-z', '--cached', '--others', '--exclude-standard')) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($start)
    if ($null -eq $process) { throw 'Could not start git' }
    $buffer = [System.IO.MemoryStream]::new()
    try {
        $process.StandardOutput.BaseStream.CopyTo($buffer)
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'git ls-files failed' }
        $paths = [System.Text.Encoding]::UTF8.GetString($buffer.ToArray())
        return $paths.Split([char[]]@([char]0), [System.StringSplitOptions]::RemoveEmptyEntries)
    }
    finally {
        $buffer.Dispose()
        $process.Dispose()
    }
}

function Test-SourceFile([string]$RelativePath) {
    $p = $RelativePath.Replace('\', '/')
    if ($p -match '(?i)(^|/)(\.git|\.vs|\.vscode|\.idea|\.venv|venv|__pycache__|\.pytest_cache|\.mypy_cache|node_modules|_deps|target|bin|obj|dist|Debug|Release|coverage|TestResults|test-results|results|logs|build(?:[-_].*)?|cmake-build(?:[-_].*)?)(/|$)') { return $false }
    if ($p -match '(?i)^opendnp3/cpp/tests/fuzz/corpus/') { return $false }
    if ($p -match '(?i)(^|/)(\.DS_Store|Thumbs\.db)$') { return $false }
    if ($p -match '(?i)\.(exe|dll|lib|obj|pdb|pch|o|a|so|dylib|class|jar|bin|elf|hex|map|gcda|gcno|profraw|zip|7z|rar|tar|gz|pdf|docx?|pptx?|xlsx?|png|jpe?g|webp|gif|bmp|ico|svg|mp[34]|avi|mov|wav|log|tmp|bak|swp|swo|cache|pyc|db|sqlite|patch|diff|pem|key|p12|pfx|crt|cer|der|jks|keystore|dnp)$') { return $false }
    if ($p -match '(?i)(^|/)(\.env(?:\..*)?|id_rsa|id_ed25519|credentials\.json|secrets?\.[^/]+)$') { return $false }
    return $true
}

function Get-Section([string]$RelativePath) {
    $p = $RelativePath.Replace('\', '/')

    if ($p -match '^(DNP3_PDD_PLAN/|AGENTS\.md$|REPO_MAP\.md$|README\.md$|\.gitignore$|opendnp3/(README\.md|CHANGELOG\.md|LICENSE|NOTICE)$)') {
        return '00_Docs_Requirements'
    }
    if ($p -match '^(DNP3-AUTOTEST-KIT/|cli/tests/|opendnp3/cpp/tests/)') {
        return '10_Tests_Fixtures'
    }
    if ($p -match '^opendnp3/cpp/lib/(src/gen/|include/opendnp3/gen/)') {
        return '08_Generated_Cpp_Sources'
    }
    if ($p -match '^opendnp3/cpp/lib/include/opendnp3/') {
        return '02_Public_Headers_API'
    }
    if ($p -match '^opendnp3/cpp/lib/src/(auth/|crypto/)') {
        return '06_Security_Crypto'
    }
    if ($p -match '^opendnp3/cpp/lib/src/master/') {
        return '04_Master'
    }
    if ($p -match '^opendnp3/cpp/lib/src/outstation/') {
        return '05_Outstation'
    }
    if ($p -match '^opendnp3/cpp/lib/src/channel/') {
        return '07_Channel_TLS_IO'
    }
    if ($p -match '^opendnp3/cpp/lib/src/') {
        return '03_Protocol_Core'
    }
    if ($p -match '^(apps/|cli/|opendnp3/cpp/examples/)') {
        return '09_Apps_CLI_Examples'
    }
    if ($p -match '^opendnp3/(java/|dotnet/)') {
        return '11_Optional_Java_DotNet'
    }
    if ($p -match '^(tools/|scripts/|CMakeLists\.txt$|opendnp3/(CMakeLists\.txt$|cpp/lib/CMakeLists\.txt$|cmake/|deps/|config/|generation/|profile/|\.github/|\.clang-|\.git|codecov\.yml$))') {
        return '01_Build_Codegen_Config'
    }
    return '99_Unclassified_Source'
}

function New-SourceZip([string]$Destination, [string[]]$RelativePaths, [string]$Repository) {
    $zip = [System.IO.Compression.ZipFile]::Open($Destination, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($relative in $RelativePaths) {
            $full = Join-Path $Repository $relative
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $full, $relative.Replace('\', '/'),
                [System.IO.Compression.CompressionLevel]::Optimal
            )
        }
    }
    finally { $zip.Dispose() }
}

$repoPath = (Resolve-Path -LiteralPath $Repo).ProviderPath
Push-Location -LiteralPath $repoPath
try {
    $gitRoot = (& git rev-parse --show-toplevel)
    if ($LASTEXITCODE -ne 0) { throw 'Not a Git repository' }
    if (([System.IO.Path]::GetFullPath($gitRoot.Trim()).TrimEnd('\', '/')) -ne $repoPath.TrimEnd('\', '/')) {
        throw 'Repo must point to the Git repository root'
    }
    $head = (& git rev-parse --short=8 HEAD).Trim()
    $branch = (& git branch --show-current).Trim()

    $sections = [ordered]@{}
    $excluded = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in @(Get-GitPaths $repoPath | Sort-Object -Unique)) {
        if (-not (Test-SourceFile $relative)) {
            $excluded.Add($relative)
            continue
        }
        $full = Join-Path $repoPath $relative
        if (-not [System.IO.File]::Exists($full)) { continue }
        $section = Get-Section $relative
        if (-not $sections.Contains($section)) {
            $sections[$section] = [System.Collections.Generic.List[string]]::new()
        }
        $sections[$section].Add($relative)
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $output = Join-Path (Split-Path $repoPath -Parent) "DNP3-SOURCE-$timestamp-$head"
    New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $all = [System.Collections.Generic.List[string]]::new()
    $manifest = [System.Collections.Generic.List[object]]::new()
    foreach ($section in $sections.Keys) {
        $files = @($sections[$section].ToArray() | Sort-Object)
        $archive = "$section.zip"
        New-SourceZip (Join-Path $output $archive) $files $repoPath
        foreach ($file in $files) {
            $all.Add($file)
            $manifest.Add([pscustomobject]@{ Archive = $archive; Path = $file })
        }
        Write-Host ("{0,-32} {1,5} files" -f $archive, $files.Count)
    }

    # One complete code snapshot in addition to the independent section ZIPs.
    New-SourceZip (Join-Path $output 'FULL_Source_Only.zip') @($all.ToArray() | Sort-Object) $repoPath
    $manifest | Export-Csv -LiteralPath (Join-Path $output 'FILE_MANIFEST.csv') -NoTypeInformation -Encoding utf8
    $excluded | Set-Content -LiteralPath (Join-Path $output 'EXCLUDED_PATHS.txt') -Encoding utf8
    @(
        "Repository: $repoPath"
        "Branch: $branch"
        "HEAD: $head"
        "Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
        "Included files: $($all.Count)"
        "Excluded files: $($excluded.Count)"
        'Current tracked and non-ignored untracked source files, including uncommitted edits.'
        'No Git history, build outputs, logs, archives, fuzz corpus or binary assets.'
        'Generated C++ source/header files are retained in their own archive.'
        'External dependencies and ignored files are NOT bundled.'
        'Review for hard-coded secrets before sharing. No tests/builds were run.'
    ) | Set-Content -LiteralPath (Join-Path $output 'PACKAGE_INFO.txt') -Encoding utf8
    Get-ChildItem -LiteralPath $output -Filter '*.zip' -File |
        ForEach-Object { '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.Name } |
        Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii

    Write-Host "`nCompleted: $output" -ForegroundColor Green
    Write-Host "Included: $($all.Count) source files | Excluded: $($excluded.Count)"
    Write-Host 'No files in the Git repository were changed.'
}
finally { Pop-Location }
