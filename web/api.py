from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, List

import os
import sys
import time
import json
import re
import subprocess
import platform
import ipaddress
from uuid import uuid4
import logging

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

from web import settings
from web.helpers import (
    build_pagination,
    flash_error,
    flash_info,
    flash_success,
    flash_warning,
    normalize_sort_dir,
    normalize_sort_key,
    parse_filters,
    pop_flashes,
)
from web.reports_db import ReportsDB
from core.radius_db import get_distinct_cities


app = FastAPI(title="MikroTik CPE DNS Doctor Dashboard")
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)
_log = logging.getLogger("uvicorn.error")
_log.info("API MODULE LOADED")

# Static + templates
app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR.resolve()), check_dir=True), name="static")
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))


# -------------------------------------------------------------------
# DB factory (compatible with older/newer ReportsDB signatures)
# -------------------------------------------------------------------
def _make_rdb() -> ReportsDB:
    """Create ReportsDB instance.

    Some older iterations of this project used ReportsDB(cfg) while newer
    versions use ReportsDB() with internal config resolution.

    To avoid breaking changes across stages, we support both.

    IMPORTANT (Stage 1 fix):
    - Current ReportsDB requires host/port/user/password/database.
      So we pass values from web.settings.
    """
    # Preferred (current): explicit connection params from settings
    # BUT: on Windows with --reload, relying on module-level settings can keep stale env values.
    # So we resolve DB_* env vars at runtime (each call) and let them override settings.
    try:
        import os

        env_host = os.getenv("DB_HOST")
        env_port = os.getenv("DB_PORT")
        env_user = os.getenv("DB_USER")
        env_pass = os.getenv("DB_PASSWORD")
        env_name = os.getenv("DB_NAME")

        host = (env_host.strip() if isinstance(env_host, str) and env_host.strip() else settings.DB_HOST)
        port = int(env_port) if env_port and str(env_port).strip() else int(settings.DB_PORT)
        user = (env_user.strip() if isinstance(env_user, str) and env_user.strip() else settings.DB_USER)

        # password can be intentionally empty, so only override if env var is set (even if empty string)
        if "DB_PASSWORD" in os.environ:
            password = os.environ.get("DB_PASSWORD", "")
        else:
            # Do NOT force an empty password from settings, because ReportsDB has safer defaults.
            _pw = getattr(settings, "DB_PASSWORD", None)
            if _pw is None:
                password = None
            else:
                _pw_s = str(_pw)
                password = _pw_s if _pw_s.strip() != "" else None

        database = (env_name.strip() if isinstance(env_name, str) and env_name.strip() else settings.DB_NAME)

        return ReportsDB(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
        )
    except TypeError:
        # If ReportsDB signature changed to no-args or cfg-based, fallback safely.
        try:
            return ReportsDB()
        except TypeError as e:
            msg = str(e)
            # Try the "cfg required" signature (legacy)
            if "cfg" not in msg:
                raise
            try:
                # Preferred: reuse core DBConfig defaults if present
                from core.db_manager import DBConfig as CoreDBConfig  # type: ignore

                return ReportsDB(cfg=CoreDBConfig())  # type: ignore[arg-type]
            except Exception:
                # Fallback: env-based config (CPEDOCTOR_DB_*)
                from dataclasses import dataclass
                import os

                @dataclass(frozen=True)
                class _EnvCfg:
                    host: str = os.environ.get("CPEDOCTOR_DB_HOST", "127.0.0.1")
                    port: int = int(os.environ.get("CPEDOCTOR_DB_PORT", "3306"))
                    user: str = os.environ.get("CPEDOCTOR_DB_USER", "root")
                    password: str = os.environ.get("CPEDOCTOR_DB_PASSWORD", "")
                    database: str = os.environ.get("CPEDOCTOR_DB_NAME", "cpedoctor")

                    charset: str = "utf8mb4"
                    autocommit: bool = True
                    connect_timeout: int = 5
                    read_timeout: int = 20
                    write_timeout: int = 20

                return ReportsDB(cfg=_EnvCfg())  # type: ignore[arg-type]


def get_db() -> ReportsDB:
    return _make_rdb()


# -----------------------------
# Helpers (template context)
# -----------------------------
def _base_ctx(
    request: Request,
    page_title: str,
    nav_active: str,
    **extra: Any,
) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "request": request,
        "app_title": settings.APP_TITLE,
        "page_title": page_title,
        "nav_active": nav_active,
        "active_tab": nav_active,
        "theme": settings.THEME,
        "cdn": settings.CDN,
        "now": datetime.now(),
        "rtl": settings.DEFAULT_RTL,
        "page_size_options": settings.PAGE_SIZE_OPTIONS,
        "reset_url": str(request.url.path),
        "flashes": pop_flashes(request),
    }
    ctx.update(extra)
    return ctx


def _mask_secrets(text: str) -> str:
    if not text:
        return ""
    masked = text
    patterns = [
        re.compile(r"(?i)(password\\s*=?\\s*)([^\\s,;]+)"),
        re.compile(r"(?i)(DB_PASSWORD\\s*=?\\s*)([^\\s,;]+)"),
    ]
    for pat in patterns:
        masked = pat.sub(r"\\1***", masked)
    return masked


def _render_error(request: Request, exc: Exception, status_code: int = 500):
    return templates.TemplateResponse(
        "error.html",
        _base_ctx(
            request,
            page_title="Error",
            nav_active="",
            error_message=_mask_secrets(str(exc)),
        ),
        status_code=status_code,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    import logging
    logging.exception("Unhandled error on %s %s", request.method, request.url.path)
    return _render_error(request, exc, status_code=500)

def safe_json(data, status_code: int = 200):
    return JSONResponse(content=jsonable_encoder(data), status_code=status_code)

@app.on_event("startup")
async def on_startup():
    _log.info("API STARTUP COMPLETE")


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    _log.info("HEALTH HIT")
    return JSONResponse({"ok": True, "service": "cpe-doctor"})

@app.get("/health/db")
def health_db():
    try:
        rdb = _make_rdb()
        data = rdb.healthcheck()
        data["ok"] = bool(data.get("ok"))
        return JSONResponse(data)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _mask_secrets(str(exc))}, status_code=503)

@app.get("/api/run/cities")
def api_run_cities():
    try:
        cities = get_distinct_cities()
    except Exception:
        cities = []
    resp = JSONResponse({"cities": cities})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/", response_class=HTMLResponse)
def root_ok():
    if not settings.DIAG_MODE:
        return RedirectResponse(url="/dashboard", status_code=302)
    _log.info("ROOT HIT")
    return HTMLResponse(
        "<!doctype html><html><head><title>OK</title></head><body><h1>OK</h1>"
        "<p>Service is running. Open <a href='/dashboard'>/dashboard</a>.</p></body></html>"
    )


@app.get("/debug/paths")
def debug_paths():
    if not settings.DIAG_MODE:
        raise HTTPException(status_code=404, detail="Not Found")
    static_dir = settings.STATIC_DIR.resolve()
    templates_dir = settings.TEMPLATES_DIR.resolve()
    static_files = []
    templates_files = []

    if static_dir.exists():
        static_files = [p.name for p in list(static_dir.iterdir())[:5]]
    if templates_dir.exists():
        templates_files = [p.name for p in list(templates_dir.iterdir())[:5]]

    return JSONResponse({
        "static_dir": str(static_dir),
        "static_exists": static_dir.exists(),
        "static_sample": static_files,
        "templates_dir": str(templates_dir),
        "templates_exists": templates_dir.exists(),
        "templates_sample": templates_files,
    })


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    try:
        f = parse_filters(request)
        rdb = _make_rdb()

        kpis = rdb.dashboard_kpis(f)
        latest_sessions = rdb.latest_sessions(f, limit=8)

        return templates.TemplateResponse(
            "pages/dashboard.html",
            _base_ctx(
                request,
                page_title="Dashboard",
                nav_active="dashboard",
                filters=f,
                kpis=kpis,
                latest_sessions=latest_sessions,
            ),
        )
    except Exception as e:
        # Show user-friendly error page while keeping server logs readable
        import logging
        logging.exception("Dashboard error")
        return _render_error(request, e, status_code=500)




@app.get("/sessions", response_class=HTMLResponse)
def sessions(request: Request):
    f = parse_filters(request)
    rdb = _make_rdb()

    total = rdb.sessions_count(f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)

    pagination = build_pagination(total=total, page=page, page_size=page_size)

    rows = rdb.sessions_list(
        filters=f,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return templates.TemplateResponse(
        "pages/sessions.html",
        _base_ctx(
            request,
            page_title="Sessions",
            nav_active="sessions",
            filters=f,
            rows=rows,
            pager=pagination,
            total=total,
        ),
    )


@app.get("/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(request: Request, session_id: int):
    f = parse_filters(request)
    rdb = _make_rdb()

    sess = rdb.session_get(session_id)
    if not sess:
        return _render_error(request, Exception(f"Session {session_id} not found"), status_code=404)

    total = rdb.session_outcomes_count(session_id, f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    pagination = build_pagination(total=total, page=page, page_size=page_size)

    outcomes = rdb.session_outcomes_list(
        session_id=session_id,
        filters=f,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return_to = request.query_params.get("return_to") or "/sessions"
    raw_kpis = sess.get("kpis") or {}
    kpis = {
        "total": sess.get("total_cpes") or total,
        "ok_count": raw_kpis.get("ok") or 0,
        "failed_count": raw_kpis.get("failed") or 0,
        "login_failed_count": raw_kpis.get("login_failed") or 0,
        "fixed_count": raw_kpis.get("fix_applied") or 0,
        "rebooted_count": raw_kpis.get("rebooted") or 0,
    }

    return templates.TemplateResponse(
        "pages/session_detail.html",
        _base_ctx(
            request,
            page_title=f"Session #{session_id}",
            nav_active="sessions",
            filters=f,
            session_id=session_id,
            session=sess,
            outcomes=outcomes,
            pager=pagination,
            total=total,
            kpis=kpis,
            return_to=return_to,
            not_found=False,
        ),
    )


@app.get("/inventory", response_class=HTMLResponse)
def inventory(request: Request):
    f = parse_filters(request)
    rdb = _make_rdb()

    total = rdb.inventory_count(f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    pagination = build_pagination(total=total, page=page, page_size=page_size)

    rows = rdb.inventory_list(
        filters=f,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return templates.TemplateResponse(
        "pages/inventory.html",
        _base_ctx(
            request,
            page_title="Inventory",
            nav_active="inventory",
            filters=f,
            rows=rows,
            pager=pagination,
            total=total,
        ),
    )


@app.get("/inventory/history", response_class=HTMLResponse)
def inventory_history(request: Request):
    f = parse_filters(request)
    rdb = _make_rdb()

    total = rdb.inventory_history_count(f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    pagination = build_pagination(total=total, page=page, page_size=page_size)

    rows = rdb.inventory_history_list(
        filters=f,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return templates.TemplateResponse(
        "pages/inventory_history.html",
        _base_ctx(
            request,
            page_title="Inventory History",
            nav_active="inventory",
            filters=f,
            rows=rows,
            pager=pagination,
            total=total,
            username=None,
        ),
    )


@app.get("/inventory/{pppoe_username}", response_class=HTMLResponse)
def inventory_history_user(request: Request, pppoe_username: str):
    f = parse_filters(request)
    f["q"] = pppoe_username
    rdb = _make_rdb()

    total = rdb.inventory_history_count(f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    pagination = build_pagination(total=total, page=page, page_size=page_size)

    rows = rdb.inventory_history_list(
        filters=f,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return templates.TemplateResponse(
        "pages/inventory_history.html",
        _base_ctx(
            request,
            page_title=f"History: {pppoe_username}",
            nav_active="inventory",
            filters=f,
            rows=rows,
            pager=pagination,
            total=total,
            username=pppoe_username,
        ),
    )


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    f = parse_filters(request)
    rdb = _make_rdb()

    items = rdb.reports_list(f)

    return templates.TemplateResponse(
        "pages/reports.html",
        _base_ctx(
            request,
            page_title="Reports",
            nav_active="reports",
            filters=f,
            items=items,
        ),
    )


@app.get("/reports/{report_key}", response_class=HTMLResponse)
def report_table(request: Request, report_key: str):
    f = parse_filters(request)
    rdb = _make_rdb()

    sort_key = normalize_sort_key(f.get("sort_key"))
    sort_dir = normalize_sort_dir(f.get("sort_dir"))

    total = rdb.report_rows_count(report_key, f)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    pagination = build_pagination(total=total, page=page, page_size=page_size)

    rows, columns = rdb.report_rows(
        report_key=report_key,
        filters=f,
        sort_key=sort_key,
        sort_dir=sort_dir,
        limit=pagination["limit"],
        offset=pagination["offset"],
    )

    return templates.TemplateResponse(
        "pages/report_table.html",
        _base_ctx(
            request,
            page_title=f"Report: {report_key}",
            nav_active="reports",
            filters=f,
            report_key=report_key,
            rows=rows,
            columns=columns,
            pager=pagination,
            total=total,
            sort_key=sort_key,
            sort_dir=sort_dir,
        ),
    )



# ============================================================
# Stage 2/3: Rules management + Run control
# ============================================================

RUNNING_PROCS: Dict[int, subprocess.Popen] = {}


def _ensure_out_dir() -> Path:
    out_dir = settings.PROJECT_ROOT / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _control_file_path(session_id: int) -> Path:
    return _ensure_out_dir() / f"control_session_{int(session_id)}.json"


def _write_control(session_id: int, payload: Dict[str, Any]) -> Path:
    p = _control_file_path(session_id)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def _kill_pid(pid: int) -> bool:
    try:
        pid = int(pid)
        if pid <= 0:
            return False

        if platform.system().lower().startswith("win"):
            # Windows: best-effort force kill
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True)
            return True

        # Linux/Mac
        import signal
        os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False


def _parse_targets_text(raw: str, max_expand: int = 4096) -> Dict[str, Any]:
    """
    Parse a user input that may contain:
    - CIDR (e.g., 192.168.100.0/24)
    - single IPs
    - comma/newline separated list
    Returns dict: {"ips": [...], "note": str}
    """
    raw = (raw or "").strip()
    if not raw:
        return {"ips": [], "note": ""}

    tokens = re.split(r"[\s,;]+", raw)
    tokens = [t.strip() for t in tokens if t and t.strip()]
    ips: list[str] = []
    expanded = 0

    for t in tokens:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            # include only hosts (exclude network/broadcast for IPv4)
            if isinstance(net, ipaddress.IPv4Network):
                hosts = list(net.hosts())
            else:
                hosts = list(net.hosts())
            if expanded + len(hosts) > max_expand:
                raise ValueError(f"CIDR too large. Max expanded IPs = {max_expand}")
            ips.extend([str(h) for h in hosts])
            expanded += len(hosts)
        else:
            ipaddress.ip_address(t)  # validate
            ips.append(t)

    # unique keep order
    seen=set()
    uniq=[]
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)

    return {"ips": uniq, "note": f"Parsed {len(uniq)} IP(s)."}


def _start_multi_cpe(cmd: list[str], env: Dict[str, str], log_file: Path) -> Dict[str, Any]:
    """Start multi_cpe.py and try to capture created session_id from stdout."""
    _ensure_out_dir()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        cmd,
        cwd=str(settings.PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    session_id: Optional[int] = None
    first_lines: list[str] = []

    start_ts = time.time()
    # Read up to N lines or for ~8 seconds to capture the session id
    while True:
        if proc.stdout is None:
            break
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            if time.time() - start_ts > 8:
                break
            continue

        first_lines.append(line.rstrip("\n"))
        with log_file.open("a", encoding="utf-8") as f:
            f.write(line)

        m = re.search(r"Session created:\s*id=(\d+)", line)
        if m:
            try:
                session_id = int(m.group(1))
            except Exception:
                session_id = None
            break

        if len(first_lines) >= 80:
            break
        if time.time() - start_ts > 8:
            break

    # If we captured a session id, keep streaming output to file in the background (best-effort)
    if session_id is not None:
        RUNNING_PROCS[session_id] = proc
        # continue reading asynchronously to keep log_file useful (best-effort)
        def _drain():
            try:
                if proc.stdout is None:
                    return
                for line in proc.stdout:
                    with log_file.open("a", encoding="utf-8") as f:
                        f.write(line)
            except Exception:
                pass

        import threading
        threading.Thread(target=_drain, daemon=True).start()

    return {
        "proc": proc,
        "session_id": session_id,
        "first_lines": first_lines,
        "log_file": str(log_file),
    }


@app.get("/run", response_class=HTMLResponse)
def run_page(request: Request):
    return templates.TemplateResponse(
        "pages/run.html",
        _base_ctx(
            request,
            page_title="Run",
            nav_active="run",
        ),
    )


@app.post("/run/start")
def run_start(
    request: Request,
    mode: str = Form("audit"),
    targets_source: str = Form("radius"),
    city: Optional[List[str]] = Form(None),
    all_cities: Optional[str] = Form(None),
    targets_text: str = Form(""),
    threads: int = Form(10),
    timeout: int = Form(10),
    batch_size: int = Form(300),
    limit: int = Form(0),
    rules_source: str = Form("db"),
    progress_interval: int = Form(2),
):
    out_dir = _ensure_out_dir()
    raw_cities: List[str] = []
    if isinstance(city, list):
        raw_cities = [c.strip() for c in city if c and str(c).strip()]
    elif isinstance(city, str) and city.strip():
        raw_cities = [city.strip()]

    # Build targets
    input_file: Optional[Path] = None
    targets_note = ""
    if targets_source == "custom":
        try:
            parsed = _parse_targets_text(targets_text, max_expand=4096)
            ips = parsed["ips"]
            targets_note = parsed.get("note", "")
            if not ips:
                flash_error(request, "No IPs found in Custom Targets.")
                return RedirectResponse(url="/run", status_code=303)
            input_file = out_dir / f"custom_targets_{uuid4().hex}.json"
            input_file.write_text(json.dumps(ips, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            flash_error(request, f"Custom targets error: {e}")
            return RedirectResponse(url="/run", status_code=303)

    # Build command
    py = sys.executable
    cmd = [
        py, "-u", str(settings.PROJECT_ROOT / "multi_cpe.py"),
        "--mode", mode,
        "--threads", str(int(threads)),
        "--timeout", str(int(timeout)),
        "--out-dir", str(out_dir),
        "--password-file", str(settings.PROJECT_ROOT / "config" / "passwords.txt"),
        "--batch-size", str(int(batch_size)),
        "--rules-source", rules_source,
        "--progress",
        "--progress-interval", str(int(progress_interval)),
    ]

    if limit and int(limit) > 0:
        cmd += ["--limit", str(int(limit))]

    if input_file is not None:
        cmd += ["--input", str(input_file)]
    else:
        # default: Radius
        cmd += ["--from-radius"]
        if all_cities:
            cmd += ["--all-cities"]
        else:
            if raw_cities:
                for c in raw_cities:
                    cmd += ["--city", c]
            else:
                flash_error(request, "Select at least one city or use All Cities.")
                return RedirectResponse(url="/run", status_code=303)

    # Environment: map DB_* to CPE_DB_* (dynamic rules) + allow Radius DB overrides
    env = dict(os.environ)
    env.setdefault("CPE_DB_HOST", env.get("DB_HOST", str(settings.DB_HOST)))
    env.setdefault("CPE_DB_PORT", env.get("DB_PORT", str(settings.DB_PORT)))
    env.setdefault("CPE_DB_USER", env.get("DB_USER", str(settings.DB_USER)))
    env.setdefault("CPE_DB_PASSWORD", env.get("DB_PASSWORD", str(settings.DB_PASSWORD)))
    env.setdefault("CPE_DB_NAME", env.get("DB_NAME", str(settings.DB_NAME)))

    # Optional Radius DB env vars
    # (core/radius_db.py reads these if present)
    if getattr(settings, "RADIUS_DB_HOST", None):
        env.setdefault("RADIUS_DB_HOST", str(settings.RADIUS_DB_HOST))
        env.setdefault("RADIUS_DB_PORT", str(settings.RADIUS_DB_PORT))
        env.setdefault("RADIUS_DB_USER", str(settings.RADIUS_DB_USER))
        env.setdefault("RADIUS_DB_PASSWORD", str(settings.RADIUS_DB_PASSWORD))
        env.setdefault("RADIUS_DB_NAME", str(settings.RADIUS_DB_NAME))

    log_file = out_dir / "web_runs" / f"run_{uuid4().hex}.log"
    started = _start_multi_cpe(cmd, env, log_file)

    sid = started.get("session_id")
    if sid:
        flash_info(request, f"Run started. Session #{sid}. {targets_note}".strip())
        return RedirectResponse(url=f"/sessions/{sid}", status_code=303)

    # fallback: show sessions list + log path
    flash_warning(request, f"Started, but could not capture session id. Log: {log_file}")
    return RedirectResponse(url="/sessions", status_code=303)


@app.post("/sessions/{session_id}/pause")
def session_pause(request: Request, session_id: int):
    p = _write_control(session_id, {"pause": True})
    flash_info(request, f"Pause requested via {p.name}")
    return RedirectResponse(url=f"/sessions/{session_id}", status_code=303)


@app.post("/sessions/{session_id}/resume")
def session_resume(request: Request, session_id: int):
    p = _write_control(session_id, {"pause": False})
    flash_info(request, f"Resume requested via {p.name}")
    return RedirectResponse(url=f"/sessions/{session_id}", status_code=303)


@app.post("/sessions/{session_id}/stop")
def session_stop(request: Request, session_id: int):
    p = _write_control(session_id, {"stop": True})
    flash_info(request, f"Stop requested via {p.name}")
    return RedirectResponse(url=f"/sessions/{session_id}", status_code=303)


@app.post("/sessions/{session_id}/kill")
def session_kill(request: Request, session_id: int):
    # request stop first
    _write_control(session_id, {"stop": True})

    # best-effort force kill
    rdb = get_db()
    prog = {}
    try:
        prog = rdb.session_progress(session_id)
    except Exception:
        prog = {}

    pid = None
    # If we have the live proc (same web process), use it
    proc = RUNNING_PROCS.get(int(session_id))
    if proc is not None and proc.poll() is None:
        try:
            pid = int(proc.pid)
        except Exception:
            pid = None

    ok = False
    if pid:
        ok = _kill_pid(pid)

    flash_warning(request, f"Force kill {'sent' if ok else 'attempted'} (pid={pid}).")
    return RedirectResponse(url=f"/sessions/{session_id}", status_code=303)


@app.get("/api/sessions/{session_id}/progress")
def api_session_progress(request: Request, session_id: int, include_rows: int = 0):
    rdb = get_db()
    f = parse_filters(request)
    page = int(f.get("page") or 1)
    page_size = int(f.get("page_size") or settings.DEFAULT_PAGE_SIZE)
    limit = max(1, page_size)
    offset = max(0, (page - 1) * page_size)
    data = rdb.session_progress(
        session_id,
        include_rows=bool(include_rows),
        filters=f,
        limit=limit,
        offset=offset,
    )
    resp = safe_json(data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/filters/options")
def api_filter_options():
    rdb = get_db()
    data = rdb.filter_options()
    return safe_json(data)


# -----------------------------
# Rules pages (Stage 2)
# -----------------------------
@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request):
    rdb = get_db()
    rules = rdb.rules_list()
    return templates.TemplateResponse(
        "pages/rules.html",
        _base_ctx(
            request,
            page_title="Rules",
            nav_active="rules",
            rules=rules,
        ),
    )


@app.get("/rules/new", response_class=HTMLResponse)
def rule_new_page(request: Request):
    return templates.TemplateResponse(
        "pages/rule_edit.html",
        _base_ctx(
            request,
            page_title="New Rule",
            nav_active="rules",
            rule=None,
            is_new=True,
        ),
    )


@app.post("/rules/new")
def rule_create(
    request: Request,
    name: str = Form(...),
    priority: int = Form(10),
    is_active: Optional[str] = Form(None),
    check_command: str = Form(...),
    warning_regex: str = Form(...),
    fix_command: str = Form(""),
):
    rdb = get_db()
    rid = rdb.create_rule(
        name=name,
        priority=int(priority),
        is_active=bool(is_active),
        check_command=check_command,
        warning_regex=warning_regex,
        fix_command=(fix_command.strip() or None),
    )
    flash_info(request, f"Rule created (id={rid}).")
    return RedirectResponse(url="/rules", status_code=303)


@app.get("/rules/{rule_id}", response_class=HTMLResponse)
def rule_edit_page(request: Request, rule_id: int):
    rdb = get_db()
    rule = rdb.get_rule(rule_id)
    if not rule:
        flash_error(request, "Rule not found.")
        return RedirectResponse(url="/rules", status_code=303)
    return templates.TemplateResponse(
        "pages/rule_edit.html",
        _base_ctx(
            request,
            page_title=f"Edit Rule #{rule_id}",
            nav_active="rules",
            rule=rule,
            is_new=False,
        ),
    )


@app.post("/rules/{rule_id}")
def rule_update(
    request: Request,
    rule_id: int,
    name: str = Form(...),
    priority: int = Form(10),
    is_active: Optional[str] = Form(None),
    check_command: str = Form(...),
    warning_regex: str = Form(...),
    fix_command: str = Form(""),
):
    rdb = get_db()
    rdb.update_rule(
        rule_id=rule_id,
        name=name,
        priority=int(priority),
        is_active=bool(is_active),
        check_command=check_command,
        warning_regex=warning_regex,
        fix_command=(fix_command.strip() or None),
    )
    flash_info(request, f"Rule updated (id={rule_id}).")
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/{rule_id}/toggle")
def rule_toggle(request: Request, rule_id: int):
    rdb = get_db()
    rdb.toggle_rule(rule_id)
    flash_info(request, f"Rule toggled (id={rule_id}).")
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/{rule_id}/delete")
def rule_delete(request: Request, rule_id: int):
    rdb = get_db()
    rdb.delete_rule(rule_id)
    flash_warning(request, f"Rule deleted (id={rule_id}).")
    return RedirectResponse(url="/rules", status_code=303)
@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    start = time.perf_counter()
    _log.info("REQ START %s %s", request.method, request.url.path)
    try:
        response = await call_next(request)
        return response
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        _log.info("REQ END %s %s %.1fms", request.method, request.url.path, elapsed_ms)
