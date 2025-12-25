# Diagnostics (Windows)

Run this to clean old uvicorn processes, start a single-process server, and test endpoints:

```powershell
.\tools\diag.ps1
```

Expected:
- `/health` returns JSON immediately
- `/` returns a small HTML page with "OK"
- `/static/app.js` returns JS content

Log file:
- `out\uvicorn_debug.log`
