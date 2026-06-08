$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()
$env:PYTHONUTF8 = "1"

$backendRoot = $PSScriptRoot
$projectRoot = Split-Path -Parent $backendRoot
$prototypeSrc = Join-Path $projectRoot "prototype\src"

$env:PYTHONPATH = "$backendRoot;$prototypeSrc"

Push-Location $backendRoot
try {
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
}
finally {
    Pop-Location
}
