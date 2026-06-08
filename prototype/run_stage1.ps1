$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()
$env:PYTHONUTF8 = "1"

$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $PSScriptRoot "src"

python -m vms_stage1.cli `
  --samples (Join-Path $projectRoot "samples") `
  --output (Join-Path $projectRoot "outputs\stage1") `
  --month "2026-05"

Write-Host ""
Write-Host "Stage 1 completed. Output directory:"
Write-Host (Join-Path $projectRoot "outputs\stage1")
