<#
.SYNOPSIS
  Build portable SearchSploit distribution (PyInstaller onefile + zip).
#>
[CmdletBinding()]
param(
    [string]$OutZip = "dist\SearchSploit-windows-x64.zip"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

python -m pip install -e ".[dev]"
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
if (Test-Path build) { Remove-Item -Recurse -Force build }

pyinstaller packaging\searchsploit.spec --noconfirm
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$stage = "dist\stage"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -Force "dist\searchsploit.exe" "$stage\searchsploit.exe"
Copy-Item -Force ".searchsploit_rc" "$stage\.searchsploit_rc"
Copy-Item -Force "scripts\install.ps1" "$stage\install.ps1"
Copy-Item -Force "README.md" "$stage\README.md"

if (Test-Path $OutZip) { Remove-Item $OutZip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $OutZip
Write-Host "Built: $OutZip"
Get-Item $OutZip | Format-List FullName, Length
