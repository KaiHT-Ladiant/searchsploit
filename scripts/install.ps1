<#
.SYNOPSIS
  Install SearchSploit for Windows: deps, Exploit-DB clone, RC, optional PATH.
.DESCRIPTION
  - pip install the local package
  - clone https://gitlab.com/exploit-database/exploitdb.git (large!)
  - write %USERPROFILE%\.searchsploit_rc
  - optionally add scripts\ to user PATH
.PARAMETER ExploitDbPath
  Destination for the exploitdb git clone. Default: C:\exploitdb
.PARAMETER Papers
  Also clone exploitdb-papers.
.PARAMETER SkipClone
  Only install the Python tool and write RC (assumes DB already present).
.PARAMETER AddToPath
  Prepend this repo's scripts\ folder to the user PATH.
#>
[CmdletBinding()]
param(
    [string]$ExploitDbPath = "C:\exploitdb",
    [string]$PapersPath = "C:\exploitdb-papers",
    [switch]$Papers,
    [switch]$SkipClone,
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Test-Command($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "==> SearchSploit for Windows installer" -ForegroundColor Cyan

if (-not (Test-Command "python")) {
    Write-Error "Python is not on PATH. Install Python 3.9+ from https://www.python.org/ or winget install Python.Python.3.12"
}

if (-not $SkipClone -and -not (Test-Command "git")) {
    Write-Error "git is not on PATH. Install Git for Windows or use -SkipClone if the DB already exists."
}

Write-Host "==> Installing Python package (editable)" -ForegroundColor Cyan
Push-Location $RepoRoot
try {
    python -m pip install --upgrade pip
    python -m pip install -e .
}
finally {
    Pop-Location
}

if (-not $SkipClone) {
    Write-Host "==> Cloning Exploit-DB (this can take a long time / several GB)" -ForegroundColor Cyan
    if (-not (Test-Path (Join-Path $ExploitDbPath ".git"))) {
        New-Item -ItemType Directory -Force -Path (Split-Path $ExploitDbPath) | Out-Null
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git $ExploitDbPath
    }
    else {
        Write-Host "    Already cloned: $ExploitDbPath (run searchsploit -u to update)"
    }

    if ($Papers) {
        if (-not (Test-Path (Join-Path $PapersPath ".git"))) {
            git clone --depth 1 https://gitlab.com/exploit-database/exploitdb-papers.git $PapersPath
        }
        else {
            Write-Host "    Already cloned: $PapersPath"
        }
    }
}

Write-Host "==> Writing $($env:USERPROFILE)\.searchsploit_rc" -ForegroundColor Cyan
$edbPosix = ($ExploitDbPath -replace "\\", "/")
$papersPosix = ($PapersPath -replace "\\", "/")
$rc = @"
##-- Program Settings
progname=`$( basename "`$0" )

##-- Exploits
files_array+=("files_exploits.csv")
path_array+=("$edbPosix")
name_array+=("Exploit")
git_array+=("https://gitlab.com/exploit-database/exploitdb.git")
package_array+=("exploitdb")

##-- Shellcodes
files_array+=("files_shellcodes.csv")
path_array+=("$edbPosix")
name_array+=("Shellcode")
git_array+=("https://gitlab.com/exploit-database/exploitdb.git")
package_array+=("exploitdb")

##-- Papers
files_array+=("files_papers.csv")
path_array+=("$papersPosix")
name_array+=("Paper")
git_array+=("https://gitlab.com/exploit-database/exploitdb-papers.git")
package_array+=("exploitdb-papers")
"@
Set-Content -Path (Join-Path $env:USERPROFILE ".searchsploit_rc") -Value $rc -Encoding UTF8

if ($AddToPath) {
    $scriptsDir = Join-Path $RepoRoot "scripts"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$scriptsDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$scriptsDir;$userPath", "User")
        $env:Path = "$scriptsDir;$env:Path"
        Write-Host "==> Added to user PATH: $scriptsDir" -ForegroundColor Cyan
        Write-Host "    Open a new terminal for PATH changes to apply everywhere."
    }
}

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host "Try:  searchsploit afd windows local"
Write-Host "Help: searchsploit -h"
Write-Host "Update DB: searchsploit -u"
