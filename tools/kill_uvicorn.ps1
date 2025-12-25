$ErrorActionPreference = "Stop"

function Get-UvicornPids {
  Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -match "uvicorn\\s+web\\.api:app" } |
    Select-Object -ExpandProperty ProcessId
}

$pids = @(Get-UvicornPids)
if ($pids.Count -eq 0) {
  Write-Host "No uvicorn web.api:app processes found."
  exit 0
}

Write-Host "Killing uvicorn processes: $($pids -join ', ')"
foreach ($pid in $pids) {
  Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
}
