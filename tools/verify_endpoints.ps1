$ErrorActionPreference = "Stop"

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

Invoke-Check "http://127.0.0.1:8000/health"
Invoke-Check "http://127.0.0.1:8000/health/db"
Invoke-Check "http://127.0.0.1:8000/static/app.js"
Invoke-Check "http://127.0.0.1:8000/dashboard"
