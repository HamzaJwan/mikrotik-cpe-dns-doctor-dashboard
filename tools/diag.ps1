$ErrorActionPreference = "Stop"

function Write-Section($text) {
  Write-Host ""
  Write-Host "=== $text ===" -ForegroundColor Cyan
}

function Get-UvicornPids {
  Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -match "uvicorn web\\.api:app" } |
    Select-Object -ExpandProperty ProcessId
}

Write-Section "Kill old uvicorn processes"
$uvicornPids = @(Get-UvicornPids)
if ($uvicornPids.Count -gt 0) {
  Write-Host "Found uvicorn PIDs: $($uvicornPids -join ', ')"
  foreach ($pid in $uvicornPids) {
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 1
} else {
  Write-Host "No uvicorn processes found."
}

Write-Section "Check port 8000 listeners"
$netstat = netstat -ano | findstr :8000
if ($netstat) {
  Write-Host $netstat
  $listenerPids = @()
  foreach ($line in $netstat) {
    if ($line -match "LISTENING\\s+(\\d+)$") {
      $listenerPids += [int]$matches[1]
    }
  }
  $listenerPids = $listenerPids | Sort-Object -Unique
  if ($listenerPids.Count -gt 0) {
    Write-Host "WARNING: PIDs listening on 8000: $($listenerPids -join ', ')"
    Write-Host "Attempting to stop them (may include python)." -ForegroundColor Yellow
    foreach ($pid in $listenerPids) {
      Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
  }
} else {
  Write-Host "No listeners on 8000."
}

Write-Section "Start uvicorn (single process, debug)"
$logPath = Join-Path $PSScriptRoot "..\\out\\uvicorn_debug.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logPath) | Out-Null

$uvicornArgs = @(
  "-m", "uvicorn", "web.api:app",
  "--host", "127.0.0.1",
  "--port", "8000",
  "--log-level", "debug"
)

$proc = Start-Process -FilePath (Join-Path $PSScriptRoot "..\\venv\\Scripts\\python.exe") `
  -ArgumentList $uvicornArgs `
  -WorkingDirectory (Join-Path $PSScriptRoot "..") `
  -RedirectStandardOutput $logPath `
  -RedirectStandardError $logPath `
  -PassThru

Write-Host "Uvicorn PID: $($proc.Id)"
Start-Sleep -Seconds 2

function Invoke-Check($url) {
  Write-Host ""
  Write-Host "GET $url"
  $raw = & curl.exe -s -D - -m 6 $url
  if (-not $raw) {
    Write-Host "No response (timeout or connection issue)." -ForegroundColor Red
    return
  }
  $lines = $raw -split "`r?`n"
  $status = $lines | Select-Object -First 1
  Write-Host "Status: $status"
  $bodyIndex = ($lines | Select-String -Pattern "^$" -SimpleMatch).LineNumber
  if ($bodyIndex) {
    $body = ($lines[$bodyIndex..($lines.Count-1)] -join "`n")
    $snippet = $body.Substring(0, [Math]::Min(200, $body.Length))
    Write-Host "Body (first 200 bytes):"
    Write-Host $snippet
  }
}

Write-Section "HTTP checks"
Invoke-Check "http://127.0.0.1:8000/health"
Invoke-Check "http://127.0.0.1:8000/"
Invoke-Check "http://127.0.0.1:8000/static/app.js"

Write-Section "Log file"
Write-Host "Log saved to: $logPath"
