param(
    [Parameter(Mandatory = $true)][string]$ArchiveName,
    [Parameter(Mandatory = $true)][string]$SourceStage
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$archivesRoot = Join-Path $projectRoot "archives"
$target = Join-Path $archivesRoot $ArchiveName
$archivesFull = [System.IO.Path]::GetFullPath($archivesRoot) + [System.IO.Path]::DirectorySeparatorChar
$targetFull = [System.IO.Path]::GetFullPath($target)

if (-not $targetFull.StartsWith($archivesFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "归档目标越界: $targetFull"
}
if (Test-Path -LiteralPath $targetFull) {
    throw "归档目录已存在: $targetFull"
}

New-Item -ItemType Directory -Path $targetFull -Force | Out-Null

function Copy-ArchiveFile {
    param([string]$Source, [string]$RelativePath)
    $destination = Join-Path $targetFull $RelativePath
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $destination
}

Get-ChildItem -LiteralPath $projectRoot -File | Where-Object {
    $_.Name -eq ".gitignore" -or $_.Extension -eq ".md"
} | ForEach-Object {
    Copy-ArchiveFile -Source $_.FullName -RelativePath (Join-Path "project-docs" $_.Name)
}

foreach ($relativeRoot in @("backend", "prototype", "docs", "outputs")) {
    $sourceRoot = Join-Path $projectRoot $relativeRoot
    if (-not (Test-Path -LiteralPath $sourceRoot)) {
        continue
    }
    Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($projectRoot.Length + 1)
        $portable = $relative.Replace("\", "/")
        if (
            $portable -match "(^|/)__pycache__(/|$)" -or
            $portable -match "(^|/)\.pytest_cache(/|$)" -or
            $portable -match "^backend/data(/|$)"
        ) {
            return
        }
        Copy-ArchiveFile -Source $_.FullName -RelativePath $relative
    }
}

$manifestFiles = Get-ChildItem -LiteralPath $targetFull -Recurse -File | Sort-Object FullName | ForEach-Object {
    [PSCustomObject]@{
        path = $_.FullName.Substring($targetFull.Length + 1).Replace("\", "/")
        size = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    archive_name = $ArchiveName
    source_stage = $SourceStage
    created_at = [DateTimeOffset]::Now.ToString("o")
    excluded = @("__pycache__", ".pytest_cache", "backend/data", "samples", "archives", ".worktrees")
    file_count = @($manifestFiles).Count
    files = @($manifestFiles)
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $targetFull "manifest.json") -Encoding utf8

Write-Output "archive=$targetFull"
Write-Output "files=$($manifest.file_count)"
