#
# Hash Master 1000 - Quick Install Script (Windows PowerShell)
#
# This script sets up HM1K for local development/testing on Windows.
#
# Usage:
#   Right-click and "Run with PowerShell"
#   or
#   powershell -ExecutionPolicy Bypass -File install.ps1
#

$ErrorActionPreference = "Stop"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Hash Master 1000 - Quick Install" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check for Python
Write-Info "Checking Python installation..."

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py -3")) {
    try {
        $version = & $cmd.Split()[0] $cmd.Split()[1..99] -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($version) {
            $major, $minor = $version.Split('.')
            if ([int]$major -ge 3 -and [int]$minor -ge 10) {
                $pythonCmd = $cmd
                Write-Success "Found Python $version"
                break
            }
        }
    } catch {
        continue
    }
}

if (-not $pythonCmd) {
    Write-Host ""
    Write-Host "Python 3.10+ not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python 3.10 or newer from:" -ForegroundColor Yellow
    Write-Host "  https://www.python.org/downloads/" -ForegroundColor White
    Write-Host ""
    Write-Host "During installation, make sure to check:" -ForegroundColor Yellow
    Write-Host "  [x] Add Python to PATH" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Determine install directory - must be run from extracted project folder
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $scriptDir "hm1k.py"))) {
    Write-Host ""
    Write-Host "hm1k.py not found in script directory!" -ForegroundColor Red
    Write-Host ""
    Write-Host "This script must be run from within the extracted HM1K project folder." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To install Hash Master 1000:" -ForegroundColor White
    Write-Host "  1. Download the latest release from https://github.com/shellntel/hm1k" -ForegroundColor Gray
    Write-Host "  2. Extract the zip file to a folder" -ForegroundColor Gray
    Write-Host "  3. Run this script from within that folder" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

$installDir = $scriptDir
Write-Info "Installing in: $installDir"
Set-Location $installDir

# Create virtual environment
Write-Info "Creating virtual environment..."
$venvPath = Join-Path $installDir ".venv"

if (Test-Path $venvPath) {
    Write-Info "Virtual environment exists, skipping creation"
} else {
    & $pythonCmd.Split()[0] $pythonCmd.Split()[1..99] -m venv .venv
}
Write-Success "Virtual environment ready"

# Get venv Python path (use explicit path to avoid system Python conflicts)
$venvPython = Join-Path $venvPath "Scripts\python.exe"

# Install dependencies using venv Python directly
Write-Info "Installing Python dependencies..."
# Use explicit venv python path with -m pip to avoid Windows pip self-upgrade issues
& $venvPython -m pip install --upgrade pip wheel setuptools -q 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "pip upgrade had warnings (this is usually OK)"
}
& $venvPython -m pip install -r requirements.txt -q
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to install dependencies!" -ForegroundColor Red
    Write-Host "Try running manually:" -ForegroundColor Yellow
    Write-Host "  $venvPython -m pip install -r requirements.txt" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Success "Dependencies installed"

# Activate virtual environment for remaining commands
$activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    $activateScript = Join-Path $venvPath "Scripts\activate.ps1"
}
. $activateScript

# Download NLTK data
Write-Info "Downloading NLTK data..."
python -c @"
import nltk
import os
nltk_data = os.path.expanduser('~/nltk_data')
os.makedirs(nltk_data, exist_ok=True)
for pkg in ['words', 'names', 'averaged_perceptron_tagger', 'punkt']:
    try:
        nltk.download(pkg, download_dir=nltk_data, quiet=True)
    except:
        pass
"@ 2>$null
Write-Success "NLTK data ready"

# Create .env file if needed
$envFile = Join-Path $installDir ".env"
if (-not (Test-Path $envFile)) {
    Write-Info "Creating .env file..."
    $secretKey = python -c "import secrets; print(secrets.token_hex(32))"

    $envContent = @"
# Hash Master 1000 Configuration
SECRET_KEY="$secretKey"
ADMIN_USERNAME="admin"
# Default password: Winter2026##
ADMIN_PASSWORD_HASH="`$2b`$12`$PzAkEQKfwFcafUK2RH08zO9Os3YFz7rq.4UqwaLHlFONDlqxncmnO"
"@
    $envContent | Out-File -FilePath $envFile -Encoding utf8
    Write-Success "Created .env with default credentials (admin / Winter2026##)"
} else {
    Write-Info ".env file exists, skipping"
}

# Create data directories
New-Item -ItemType Directory -Force -Path "data\sessions" 2>$null | Out-Null
New-Item -ItemType Directory -Force -Path "data\uploads" 2>$null | Out-Null
New-Item -ItemType Directory -Force -Path "flask_session" 2>$null | Out-Null

# Generate SSL certificates
$certFile = Join-Path $installDir "cert.pem"
$keyFile = Join-Path $installDir "key.pem"

if ((-not (Test-Path $certFile)) -or (-not (Test-Path $keyFile))) {
    Write-Info "Generating self-signed SSL certificate..."

    # Try OpenSSL if available
    $opensslPath = $null
    $possiblePaths = @(
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\OpenSSL-Win64\bin\openssl.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $opensslPath = $path
            break
        }
    }

    if ($opensslPath -or (Get-Command openssl -ErrorAction SilentlyContinue)) {
        $openssl = if ($opensslPath) { $opensslPath } else { "openssl" }
        & $openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=HM1K/CN=localhost" 2>$null
        Write-Success "SSL certificate generated"
    } else {
        Write-Warn "OpenSSL not found. Generating certificate with Python..."
        python -c @"
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'State'),
    x509.NameAttribute(NameOID.LOCALITY_NAME, 'City'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'HM1K'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
])
cert = (x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(key, hashes.SHA256()))

with open('key.pem', 'wb') as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open('cert.pem', 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
"@ 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "SSL certificate generated with Python"
        } else {
            Write-Warn "Could not generate SSL certificate. The app will still work but may show certificate warnings."
        }
    }
} else {
    Write-Info "SSL certificates exist, skipping"
}

# Create start script
$startScript = @"
@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
echo Starting Hash Master 1000...
echo Access at: https://127.0.0.1:8443
echo Login: admin / Winter2026## (unless changed)
echo.
python hm1k.py
pause
"@
$startScript | Out-File -FilePath "start.bat" -Encoding ascii

# Create PowerShell start script
$startPs1 = @'
# Start Hash Master 1000
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir
. .\.venv\Scripts\Activate.ps1
Write-Host "Starting Hash Master 1000..." -ForegroundColor Green
Write-Host "Access at: https://127.0.0.1:8443" -ForegroundColor Cyan
Write-Host "Login: admin / Winter2026## (unless changed)" -ForegroundColor Yellow
Write-Host ""
python hm1k.py
'@
$startPs1 | Out-File -FilePath "start.ps1" -Encoding utf8

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start Hash Master 1000:" -ForegroundColor White
Write-Host ""
Write-Host "  Option 1: Double-click start.bat" -ForegroundColor Yellow
Write-Host "  Option 2: Run .\start.ps1 in PowerShell" -ForegroundColor Yellow
Write-Host ""
Write-Host "Or manually:" -ForegroundColor White
Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "  python hm1k.py" -ForegroundColor Gray
Write-Host ""
Write-Host "Access the app at: https://127.0.0.1:8443" -ForegroundColor Cyan
Write-Host "Default login: admin / Winter2026##" -ForegroundColor White
Write-Host ""
Write-Warn "Change the default password in .env for security!"
Write-Host ""
Read-Host "Press Enter to exit"
