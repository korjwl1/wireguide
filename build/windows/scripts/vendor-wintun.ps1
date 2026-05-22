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
$url     = "https://www.wintun.net/builds/wintun-$Version.zip"
$expect  = $Sha256.ToLower()
$tmpZip  = Join-Path $env:TEMP "wintun-$Version.zip"
$tmpDir  = Join-Path $env:TEMP ("wintun-extract-" + [guid]::NewGuid())

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $tmpZip

$actual = (Get-FileHash -Algorithm SHA256 $tmpZip).Hash.ToLower()
if ($actual -ne $expect) {
    throw "wintun.zip SHA256 mismatch. expected=$expect actual=$actual"
}

Expand-Archive -Force -Path $tmpZip -DestinationPath $tmpDir
$src = Join-Path $tmpDir "wintun\bin\$dllArch\wintun.dll"
if (-not (Test-Path $src)) {
    throw "wintun.dll not found at $src (unknown arch: $dllArch)"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $src (Join-Path $OutDir 'wintun.dll') -Force
Remove-Item -Recurse -Force $tmpDir
Write-Host "Bundled $dllArch wintun.dll to $OutDir"
