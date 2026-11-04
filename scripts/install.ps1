# install.ps1 — one-line installer for shuang (Windows).
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/rasuvaeff/shuang/master/scripts/install.ps1 | iex
#
# Override install location with $env:INSTALL_DIR:
#   $env:INSTALL_DIR = "C:\Tools"; irm ... | iex
#
# To pin both this script and its release asset, fetch this file from a release tag:
#   $env:VERSION = "v0.2.0"; irm "https://raw.githubusercontent.com/rasuvaeff/shuang/$env:VERSION/scripts/install.ps1" | iex
$ErrorActionPreference = "Stop"

$Owner = "rasuvaeff"
$Repo = "shuang"
if ($env:INSTALL_DIR) {
    $InstallDir = $env:INSTALL_DIR
} else {
    $InstallDir = "$env:LOCALAPPDATA\Programs\shuang"
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "shuang: only 64-bit Windows is supported by published binaries"
}
$target = "x86_64-pc-windows-msvc"
$asset = "shuang-$target.zip"
if ($env:VERSION) {
    $baseUrl = "https://github.com/$Owner/$Repo/releases/download/$($env:VERSION)"
    $versionLabel = $env:VERSION
} else {
    $baseUrl = "https://github.com/$Owner/$Repo/releases/latest/download"
    $versionLabel = "latest"
}
$url = "$baseUrl/$asset"

Write-Host "==> Detecting platform... $target"
Write-Host "==> Downloading $asset ($versionLabel)..."
# Expand-Archive refuses any path that does not end in .zip, so the temporary file
# must carry that extension — New-TemporaryFile alone (.tmp) makes extraction fail.
$tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("shuang-" + [System.IO.Path]::GetRandomFileName() + ".zip")
$tmpSum = "$tmpZip.sha256"
try {
    Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing
} catch {
    throw "shuang: download failed: $url`n$_"
}

# The release publishes <asset>.sha256 next to every archive. Verification is mandatory:
# this script is meant to be piped into iex, so a tampered download must fail closed.
Write-Host "==> Verifying checksum..."
try {
    Invoke-WebRequest -Uri "$url.sha256" -OutFile $tmpSum -UseBasicParsing
} catch {
    Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue
    throw "shuang: could not fetch the published checksum: $url.sha256`n$_"
}
try {
    $expected = ((Get-Content -Path $tmpSum -TotalCount 1) -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmpZip).Hash.ToLower()
    if (-not $expected) {
        throw "shuang: published checksum for $asset is empty"
    }
    if ($actual -ne $expected) {
        throw "shuang: checksum mismatch for $asset`n    expected: $expected`n    actual:   $actual"
    }
} catch {
    Remove-Item $tmpZip, $tmpSum -Force -ErrorAction SilentlyContinue
    throw
}

Write-Host "==> Extracting to $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
try {
    Expand-Archive -Path $tmpZip -DestinationPath $InstallDir -Force
} finally {
    Remove-Item $tmpZip, $tmpSum -Force -ErrorAction SilentlyContinue
}

$binPath = Join-Path $InstallDir "shuang.exe"

# --- PATH ---------------------------------------------------------------------
# Compare entry by entry: a `-like "*$InstallDir*"` substring test matches a different
# directory that merely starts with the same path and would skip the update.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$entries = @($userPath -split ';' | ForEach-Object { $_.TrimEnd('\') } | Where-Object { $_ })
if ($entries -notcontains $InstallDir.TrimEnd('\')) {
    Write-Host "==> Adding $InstallDir to user PATH..."
    $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path += ";$InstallDir"
}

Write-Host "==> Installed:"
& $binPath --version
Write-Host ""
Write-Host "Run 'shuang --help' (or 'shuang -h') to get started."
Write-Host "(If 'shuang' is not found, open a new terminal so PATH is refreshed.)"
