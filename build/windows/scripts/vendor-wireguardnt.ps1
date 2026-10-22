#Requires -Version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$Sha256,
    [Parameter(Mandatory=$true)][string]$Arch,
    [Parameter(Mandatory=$true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$dllArch = if ($Arch -eq '386') { 'x86' } else { $Arch }
$url     = "https://download.wireguard.com/wireguard-nt/wireguard-nt-$Version.zip"
$expect  = $Sha256.ToLower()
$tmpZip  = Join-Path $env:TEMP "wireguard-nt-$Version.zip"
$tmpDir  = Join-Path $env:TEMP ("wireguard-nt-extract-" + [guid]::NewGuid())

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $tmpZip

# .NET APIs instead of Get-FileHash / Expand-Archive: GitHub Actions Windows
# runners enforce an AppLocker policy that blocks several of those cmdlets.
$stream = [System.IO.File]::OpenRead($tmpZip)
try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($stream)
    $actual = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
} finally {
    $stream.Dispose()
}
if ($actual -ne $expect) {
    throw "wireguard-nt.zip SHA256 mismatch. expected=$expect actual=$actual"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
[System.IO.Compression.ZipFile]::ExtractToDirectory($tmpZip, $tmpDir)
$src = Join-Path $tmpDir "wireguard-nt\bin\$dllArch\wireguard.dll"
if (-not (Test-Path $src)) {
    throw "wireguard.dll not found at $src (unknown arch: $dllArch)"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $src (Join-Path $OutDir 'wireguard.dll') -Force
Copy-Item (Join-Path $tmpDir 'wireguard-nt\LICENSE.txt') (Join-Path $OutDir 'wireguard-nt-LICENSE.txt') -Force
Remove-Item -Recurse -Force $tmpDir
Write-Host "Bundled $dllArch wireguard.dll and its license to $OutDir"
