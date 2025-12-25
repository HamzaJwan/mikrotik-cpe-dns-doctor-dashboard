$ErrorActionPreference = "Stop"

param(
  [switch]$Reload
)

function Write-Section($text) {
  Write-Host ""
  Write-Host "=== $text ===" -ForegroundColor Cyan
}

function Get-ListeningPids {
  $lines = netstat -ano | findstr :8000
  $pids = @()
  foreach ($line in $lines) {
    if ($line -match "LISTENING\\s+(\\d+)$") {
      $pids += [int]$matches[1]
    }
  }
  $pids | Sort-Object -Unique
}

function Get-CommandLine($pid) {
  try {
    (Get-CimInstance Win32_Process -Filter "ProcessId=$pid").CommandLine
  } catch {
    ""
  }
}

Write-Section "Port 8000 guard"
$listenerPids = @(Get-ListeningPids)
if ($listenerPids.Count -gt 0) {
  Write-Host "Found listeners on :8000" -ForegroundColor Yellow
  foreach ($pid in $listenerPids) {
    $cmd = Get-CommandLine $pid
    Write-Host "PID $pid => $cmd"
  }

  $uvicornPids = @()
  $nonUvicorn = @()
  foreach ($pid in $listenerPids) {
    $cmd = Get-CommandLine $pid
    if ($cmd -match "uvicorn\\s+web\\.api:app") {
      $uvicornPids += $pid
    } else {
      $nonUvicorn += $pid
    }
  }

  if ($nonUvicorn.Count -gt 0) {
    Write-Host "Port 8000 is in use by non-uvicorn process. Stop it manually and rerun." -ForegroundColor Red
    exit 1
  }

  if ($uvicornPids.Count -gt 0) {
    Write-Host "Killing uvicorn web.api:app PIDs: $($uvicornPids -join ', ')"
    foreach ($pid in ($uvicornPids | Sort-Object -Unique)) {
      Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
  }
} else {
  Write-Host "Port 8000 is free."
}

Write-Section "Start uvicorn (single process)"
$pythonPath = Join-Path $PSScriptRoot "..\\venv\\Scripts\\python.exe"
if (-not (Test-Path $pythonPath)) {
  $pythonPath = "python"
}

$args = @(
  "-m", "uvicorn", "web.api:app",
  "--host", "127.0.0.1",
  "--port", "8000",
  "--log-level", "debug"
)
if ($Reload) {
  $args += "--reload"
}

Write-Host "Running: $pythonPath $($args -join ' ')"
& $pythonPath @args
