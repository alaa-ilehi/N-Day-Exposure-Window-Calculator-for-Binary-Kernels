# Builds the Docker image and installs a wrapper so 'patch-shadow' works from any terminal.
# Run from the project root: .\install.ps1

$ErrorActionPreference = "Stop"

$IMAGE   = "patch-shadow"
$BIN_DIR = "$env:USERPROFILE\bin"
$WRAPPER = "$BIN_DIR\patch-shadow.bat"

Write-Host "=== Patch Shadow installer ===" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker not found. Install Docker Desktop and retry."; exit 1
}
docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker daemon not running. Start Docker Desktop and retry."; exit 1
}

Write-Host "[1/3] Building Docker image '$IMAGE'..." -ForegroundColor Yellow
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
docker build -t $IMAGE "$SCRIPT_DIR"
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }

Write-Host "[2/3] Installing wrapper to $WRAPPER..." -ForegroundColor Yellow
if (-not (Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR | Out-Null }

"@echo off`ndocker run --rm -i -v ""%CD%:/data"" -w /data $IMAGE %*" | Set-Content -Encoding ASCII $WRAPPER

Write-Host "[3/3] Updating PATH..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$BIN_DIR*") {
    [Environment]::SetEnvironmentVariable("PATH", "$BIN_DIR;$userPath", "User")
    Write-Host "Added $BIN_DIR to PATH. Restart your terminal." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Usage from any directory:" -ForegroundColor Green
Write-Host "  patch-shadow --help"
Write-Host "  patch-shadow scan kernel.elf"
Write-Host "  patch-shadow list-cves"
