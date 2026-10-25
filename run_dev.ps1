# Starts the dev server with a stable JWT secret and the Postgres URL.
# Usage:  .\run_dev.ps1

if (Test-Path .\.venv\Scripts\Activate.ps1) {
    . .\.venv\Scripts\Activate.ps1
}

# 1) JWT secret: created once, then reused on every start.
if (-not (Test-Path .\.jwt_secret)) {
    python -c "import secrets; print(secrets.token_urlsafe(48))" |
        Out-File -Encoding ascii -NoNewline .\.jwt_secret
    Write-Host "Created a new JWT secret in .jwt_secret"
}
$env:JWT_SECRET_KEY = (Get-Content .\.jwt_secret -Raw).Trim()

# 2) Database URL: asks for the password only if DATABASE_URL is not set.
if (-not $env:DATABASE_URL) {
    $secure = Read-Host "Postgres password" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    $pw = [uri]::EscapeDataString($plain)   # handles @ # : / in passwords
    $env:DATABASE_URL = "postgresql+psycopg2://postgres:$pw@127.0.0.1:5432/sih26237"
}

if ($args -contains "https") {
    $env:PUBLIC_BASE_URL = "https://127.0.0.1:8443"
    python run_https.py
} else {
    uvicorn main:app --reload --port 8001
}