$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()
$env:PYTHONUTF8 = "1"

$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = "$PSScriptRoot;$projectRoot\prototype\src"

Push-Location $PSScriptRoot
try {
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir $PSScriptRoot
}
finally {
    Pop-Location
}
