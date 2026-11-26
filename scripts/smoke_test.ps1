<#
.SYNOPSIS
  Run fixture-based smoke checks without a full Exploit-DB clone.
#>
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$fixRoot = (Resolve-Path "tests\fixtures\exploitdb").Path -replace "\\", "/"
$rc = (Get-Content "tests\fixtures\.searchsploit_rc" -Raw).Replace("FIXTURE_ROOT", $fixRoot)
$rcPath = Join-Path $env:TEMP "searchsploit_smoke_rc"
Set-Content -Path $rcPath -Value $rc -Encoding UTF8
$env:SEARCHSPLOIT_RC = $rcPath

python -m pip install -e . | Out-Null

Write-Host "[1] search afd windows local"
python -m searchsploit afd windows local | Out-Null
Write-Host "[2] --cve"
python -m searchsploit --cve 2021-44228 --id | Out-Null
Write-Host "[3] -p 39446"
python -m searchsploit -p 39446 | Out-Null
Write-Host "[4] --nmap"
python -m searchsploit --nmap tests\fixtures\scan.xml | Out-Null
Write-Host "[5] CSV comma title (exact)"
python -m searchsploit -j -e "WordPress Plugin Example, with comma - XSS" | Out-Null
Write-Host "Smoke tests OK" -ForegroundColor Green
