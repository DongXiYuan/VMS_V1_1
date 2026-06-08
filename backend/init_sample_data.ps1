$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$baseUrl = "http://127.0.0.1:8000"

Write-Host "Importing sample assets..."
$assets = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/dev/import-assets-sample"
$assets | ConvertTo-Json

Write-Host ""
Write-Host "Importing sample vulnerabilities..."
$body = @{ scan_month = "2026-05" } | ConvertTo-Json
$batch = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/dev/import-vulnerabilities-sample" -ContentType "application/json" -Body $body
$batch | ConvertTo-Json -Depth 5

Write-Host ""
Write-Host "Sample data initialized."
