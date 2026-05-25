<#
.SYNOPSIS
    Installs patch-shadow so it can be run from any terminal on Windows.

.DESCRIPTION
    1. Builds the Docker image 'patch-shadow'.
    2. Creates a wrapper batch file in %USERPROFILE%\bin\ that calls
       `docker run` transparently, mounting your current directory as /data.
    3. Adds %USERPROFILE%\bin to your user PATH if it isn't already there.

.EXAMPLE
    # Run from the project root:
    .\install.ps1

    # Then from any directory:
    patch-shadow --help
    patch-shadow scan kernel.elf
    patch-shadow list-cves
#>

$ErrorActionPreference = "Stop"

$IMAGE    = "patch-shadow"
$BIN_DIR  = "$env:USERPROFILE\bin"
$WRAPPER  = "$BIN_DIR\patch-shadow.bat"

Write-Host ""
Write-Host "=== Patch Shadow installer ===" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check Docker ─────────────────────────────────────────────────────────
Write-Host "[1/3] Checking Docker..." -ForegroundColor Yellow
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed or not in PATH. Install Docker Desktop and retry."
    exit 1
}
docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker daemon is not running. Start Docker Desktop and retry."
    exit 1
}
Write-Host "      Docker OK" -ForegroundColor Green

# ── 2. Build image ───────────────────────────────────────────────────────────
Write-Host "[2/3] Building Docker image '$IMAGE' (first run may take a minute)..." -ForegroundColor Yellow
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
docker build -t $IMAGE "$SCRIPT_DIR"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed."
    exit 1
}
Write-Host "      Image built OK" -ForegroundColor Green

# ── 3. Install wrapper ───────────────────────────────────────────────────────
Write-Host "[3/3] Installing wrapper to $WRAPPER..." -ForegroundColor Yellow

if (-not (Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Path $BIN_DIR | Out-Null
}

@"
@echo off
docker run --rm -i -v "%CD%:/data" -w /data $IMAGE %*
"@ | Set-Content -Encoding ASCII $WRAPPER

# Add BIN_DIR to user PATH if not already present
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$BIN_DIR*") {
    [Environment]::SetEnvironmentVariable("PATH", "$BIN_DIR;$userPath", "User")
    Write-Host "      Added $BIN_DIR to user PATH." -ForegroundColor Green
    Write-Host "      IMPORTANT: Restart your terminal for PATH to take effect." -ForegroundColor Yellow
} else {
    Write-Host "      $BIN_DIR already in PATH." -ForegroundColor Green
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage (from any directory):"
Write-Host "  patch-shadow --help"
Write-Host "  patch-shadow list-cves"
Write-Host "  patch-shadow scan kernel.elf"
Write-Host "  patch-shadow scan kernel.elf --output json"
Write-Host ""
