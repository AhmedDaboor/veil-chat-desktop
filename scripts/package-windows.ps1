$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktopDirectory = (Resolve-Path (Join-Path $scriptDirectory '..')).Path
$outputDirectory = $env:VEIL_CHAT_PACKAGE_OUTPUT
if ([string]::IsNullOrWhiteSpace($outputDirectory)) {
    $outputDirectory = Join-Path $desktopDirectory 'artifacts\win-x64'
} elseif (-not [IO.Path]::IsPathRooted($outputDirectory)) {
    $outputDirectory = Join-Path $desktopDirectory $outputDirectory
}
$outputDirectory = [IO.Path]::GetFullPath($outputDirectory)
$dotnetCommand = if ([string]::IsNullOrWhiteSpace($env:DOTNET_EXE)) { 'dotnet' } else { $env:DOTNET_EXE }

if ($env:OS -ne 'Windows_NT') {
    throw 'Run this script from Windows PowerShell on Windows x64.'
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Rust Cargo is required.'
}
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $outputDirectory) -Force | Out-Null
} else {
    throw "Output already exists; choose a new VEIL_CHAT_PACKAGE_OUTPUT path: $outputDirectory"
}

Push-Location $desktopDirectory
try {
    & cargo build --manifest-path rust-worker/Cargo.toml --release --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'Locked offline Rust worker build failed.' }

    & $dotnetCommand publish src/VeilChat.Desktop/VeilChat.Desktop.csproj `
        --configuration Release --runtime win-x64 --self-contained false --no-restore `
        --output $outputDirectory
    if ($LASTEXITCODE -ne 0) { throw '.NET Windows publish failed.' }

    $workerDirectory = Join-Path $outputDirectory 'worker'
    $documentationDirectory = Join-Path $outputDirectory 'docs'
    $scriptsDirectory = Join-Path $outputDirectory 'scripts'
    New-Item -ItemType Directory -Path $workerDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $documentationDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $scriptsDirectory -Force | Out-Null
    Copy-Item rust-worker/target/release/veil-chat-ipc-worker.exe `
        (Join-Path $workerDirectory 'veil-chat-ipc-worker.exe')
    Copy-Item scripts/launch-windows.cmd (Join-Path $outputDirectory 'launch-windows.cmd')
    Copy-Item scripts/live-matrix-smoke.py (Join-Path $scriptsDirectory 'live-matrix-smoke.py')
    Copy-Item docs/live-matrix-test.md (Join-Path $documentationDirectory 'live-matrix-test.md')
    Copy-Item README.md $outputDirectory
    Copy-Item SECURITY.md $outputDirectory
    Copy-Item SECURITY_STATUS.md $outputDirectory
    Copy-Item CONTRIBUTING.md $outputDirectory
} finally {
    Pop-Location
}

Write-Output "Created framework-dependent Windows package at $outputDirectory"
Write-Output 'Set VEIL_CHAT_TOR_EXECUTABLE to a trusted Tor binary before launching.'
