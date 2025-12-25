# multi_cpe.py
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.db_manager import DBManager, DBConfig, IPAlreadyReserved
from core.radius_db import get_online_cpe_by_cities


# =========================================================
# JSON helpers
# =========================================================

def load_json(path: str) -> Any:
    abs_path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"JSON file not found: {path} (abs: {abs_path})")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def fmt_hms(seconds: float) -> str:
    if seconds < 0:
        seconds = 0
    s = int(seconds)
    h = s // 3600
    m = (s % 3600) // 60
    s2 = s % 60
    if h > 0:
        return f"{h:02d}:{m:02d}:{s2:02d}"
    return f"{m:02d}:{s2:02d}"


# =========================================================
# Targets normalization
# =========================================================

def normalize_targets(obj: Any) -> List[Dict[str, Any]]:
    """
    Normalize targets into list of dict items:
      [{"ip": "...", "city": "...", "username": "..."}]

    Supports:
      - ["10.0.0.1", "10.0.0.2"]
      - [{"ip":"..."}, ...]
      - {"targets":[...]} / {"ips":[...]} / {"safe_list":[...]}
      - {"10.16.16.89": {...}, "10.16.16.92": {...}}  (dict keyed by IP)
    """
    if obj is None:
        return []

    if isinstance(obj, dict):
        for key in ("targets", "ips", "safe_list", "items", "data"):
            if key in obj:
                return normalize_targets(obj[key])

        if "ip" in obj:
            return [obj]

        out: List[Dict[str, Any]] = []
        for k, v in obj.items():
            ip = str(k).strip()
            if not ip:
                continue
            if isinstance(v, dict):
                t = {"ip": ip, **v}
            else:
                t = {"ip": ip}
            out.append(t)
        return out

    if isinstance(obj, list):
        out2: List[Dict[str, Any]] = []
        for item in obj:
            if isinstance(item, str):
                out2.append({"ip": item})
            elif isinstance(item, dict) and "ip" in item:
                out2.append(item)
        return out2

    return []


def dedup_targets(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Dedup by IP (keep first).
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for t in targets:
        ip = str(t.get("ip", "")).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(t)
    return out


def load_targets_from_file(path: str, city: Optional[str]) -> List[Dict[str, Any]]:
    data = load_json(path)
    targets = normalize_targets(data)

    if city:
        filtered = []
        for t in targets:
            t_city = (t.get("city") or t.get("branch") or t.get("group"))
            if t_city is None:
                filtered.append(t)
            else:
                if str(t_city).strip().lower() == city.strip().lower():
                    filtered.append(t)
        targets = filtered

    return dedup_targets(targets)


# =========================================================
# main.py invocation (library call)
# =========================================================

def invoke_main_single(ip: str, mode: str, city: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls main.process_cpe(...) as a library call.

    main.py MUST expose:
      process_cpe(ip, mode_raw=..., timeout=..., user=..., password=..., password_file=..., city=..., save_logs=..., rules_source=...)
    """
    import importlib
    main_mod = importlib.import_module("main")

    if not hasattr(main_mod, "process_cpe") or not callable(getattr(main_mod, "process_cpe")):
        raise RuntimeError("main.py must expose a callable function: process_cpe(...)")

    fn = getattr(main_mod, "process_cpe")

    mapped = {
        "mode_raw": mode,
        "timeout": extra.get("timeout", 10),
        "user": extra.get("telnet_user", "admin"),
        "password": extra.get("password"),
        "password_file": extra.get("password_file"),
        "save_logs": bool(extra.get("save_logs", False)),
        "rules_source": extra.get("rules_source", "db"),
        "city": city,
    }

    return fn(ip=ip, **mapped)


def extract_fields(result: Dict[str, Any]) -> Tuple[Dict[str, Any], Any, Any, str]:
    if not isinstance(result, dict):
        return ({"status": "failed", "_error": "result_not_dict"}, [], None, "")

    summary = result.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}

    warnings = result.get("warnings") or []
    rules_result = result.get("rules_result") or result.get("rules") or result.get("rule_results")
    raw_output_text = result.get("raw_output_text") or result.get("raw") or result.get("output") or ""

    if "warning_count" not in summary:
        summary["warning_count"] = len(warnings) if isinstance(warnings, list) else int(result.get("warning_count") or 0)

    if "status" not in summary:
        summary["status"] = result.get("status") or "unknown"

    return summary, warnings, rules_result, str(raw_output_text or "")


def classify_status(summary: Dict[str, Any]) -> str:
    status = str(summary.get("status") or "").lower()
    if status in ("ok", "warn", "fixed", "unreachable", "failed"):
        return status

    err = str(summary.get("_error") or "").lower()
    if "login_failed" in err or "auth" in err:
        return "failed"
    if "timed out" in err or "timeout" in err or "unreachable" in err:
        return "unreachable"
    return status or "unknown"


# =========================================================
# DB config
# =========================================================

def build_db_config(args: argparse.Namespace) -> DBConfig:
    """
    DBConfig is frozen=True; build a new instance with overrides.
    """
    base = DBConfig()
    return DBConfig(
        host=args.db_host or base.host,
        port=int(args.db_port) if args.db_port else base.port,
        user=args.db_user or base.user,
        password=args.db_pass or base.password,
        database=args.db_name or base.database,
        charset=getattr(base, "charset", "utf8mb4"),
        autocommit=getattr(base, "autocommit", True),
        connect_timeout=getattr(base, "connect_timeout", 5),
        read_timeout=getattr(base, "read_timeout", 2),
        write_timeout=getattr(base, "write_timeout", 2),
    )


# =========================================================
# Control (pause/resume/stop)
# =========================================================

class ControlState:
    def __init__(self) -> None:
        self.pause = False
        self.stop = False
        self.reason = ""


class ControlFile:
    """
    JSON schema:
      {"pause": false, "stop": false, "reason": ""}

    - pause=true  => stop submitting new tasks (running tasks continue)
    - stop=true   => stop scheduling + exit loop (running tasks may finish based on pool state)
    """
    def __init__(self, path: str, poll_interval: float = 1.0) -> None:
        self.path = path
        self.poll_interval = poll_interval
        self.state = ControlState()
        self._last_mtime = 0.0
        self._lock = threading.Lock()

    def ensure_exists(self) -> None:
        if not self.path:
            return
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            save_json(self.path, {"pause": False, "stop": False, "reason": ""})

    def read_state(self) -> ControlState:
        if not self.path:
            return self.state
        try:
            mtime = os.path.getmtime(self.path)
            if mtime == self._last_mtime:
                return self.state
            data = load_json(self.path)
            self._last_mtime = mtime
            with self._lock:
                self.state.pause = bool(data.get("pause", False))
                self.state.stop = bool(data.get("stop", False))
                self.state.reason = str(data.get("reason", "") or "")
            return self.state
        except Exception:
            return self.state

    def wait_if_paused(self, stop_event: threading.Event) -> None:
        while True:
            st = self.read_state()
            if st.stop:
                return
            if not st.pause:
                return
            if stop_event.is_set():
                return
            time.sleep(self.poll_interval)


# =========================================================
# Worker
# =========================================================

def _clean_username(u: Optional[str]) -> Optional[str]:
    if u is None:
        return None
    u = str(u).strip()
    if not u or u.upper() == "UNKNOWN":
        return None
    return u


def worker_process_target(
    db: DBManager,
    session_id: int,
    target: Dict[str, Any],
    mode: str,
    main_extra: Dict[str, Any],
    artifacts_lock: threading.Lock,
    artifacts: Dict[str, Any],
) -> Dict[str, Any]:
    ip = str(target.get("ip") or "").strip()
    city = target.get("city")
    radius_username = target.get("username")  # stable in your company

    action = mode

    # Avoid duplicate IPs inside same session
    try:
        db.reserve_ip_once(session_id=session_id, ip=ip, action=action)
    except IPAlreadyReserved:
        return {"ip": ip, "skipped": True, "reason": "already_reserved_in_session"}

    started = time.time()
    try:
        result = invoke_main_single(ip=ip, mode=mode, city=city, extra=main_extra)
        summary, warnings, rules_result, raw_output_text = extract_fields(result)
        summary["_duration_ms"] = int((time.time() - started) * 1000)
    except Exception as e:
        summary = {
            "status": "failed",
            "login_success": None,
            "password_used": None,
            "password_used_is_empty": None,
            "warning_count": 0,
            "fix_applied": None,
            "pppoe_username": None,
            "_error": str(e),
            "_duration_ms": int((time.time() - started) * 1000),
        }
        warnings = []
        rules_result = None
        raw_output_text = ""

    # Prefer PPPoE username from device; fallback to Radius username (DMA)
    pppoe_username = _clean_username(summary.get("pppoe_username")) or _clean_username(radius_username) or "UNKNOWN"

    # Inventory upsert (latest state per username)
    now = datetime.now()
    cpe_id = db.upsert_inventory_latest_state(
        ip=ip,
        pppoe_username=pppoe_username,
        city=city,
        last_login_success=summary.get("login_success"),
        password_used=summary.get("password_used"),
        password_is_empty=summary.get("password_used_is_empty"),
        last_status=str(summary.get("status") or "unknown"),
        last_fix_applied=summary.get("fix_applied"),
        last_warning_count=int(summary.get("warning_count") or 0),
        last_session_id=session_id,
        last_seen_at=now,
        summary=summary,
        warnings=warnings,
    )

    # Logs row
    db.log_attempt(
        session_id=session_id,
        ip=ip,
        action=action,
        status=str(summary.get("status") or "unknown"),
        login_success=summary.get("login_success"),
        password_used=summary.get("password_used"),
        password_is_empty=summary.get("password_used_is_empty"),
        warning_count=int(summary.get("warning_count") or 0),
        fix_applied=summary.get("fix_applied"),
        rebooted=summary.get("reboot_executed"),
        rules_result=rules_result,
        raw_output_text=raw_output_text,
        cpe_id=cpe_id if cpe_id else None,
    )

    cls = classify_status(summary)

    with artifacts_lock:
        artifacts["results"].append({
            "ip": ip,
            "city": city,
            "radius_username": radius_username,
            "pppoe_username": pppoe_username,
            "summary": summary,
        })

        if warnings:
            artifacts["warnings"][ip] = warnings

        artifacts["lists"].setdefault(cls, []).append(ip)

        artifacts["stats"]["total_done"] += 1
        artifacts["stats"][cls] = artifacts["stats"].get(cls, 0) + 1

        # Counters (for web-ready summary)
        if bool(summary.get("fix_applied")):
            artifacts["stats"]["fix_applied"] = artifacts["stats"].get("fix_applied", 0) + 1
        if bool(summary.get("reboot_executed")):
            artifacts["stats"]["rebooted"] = artifacts["stats"].get("rebooted", 0) + 1
        if summary.get("login_success") is False:
            artifacts["stats"]["login_failed"] = artifacts["stats"].get("login_failed", 0) + 1
        if summary.get("password_used_is_empty") is True:
            artifacts["stats"]["empty_password"] = artifacts["stats"].get("empty_password", 0) + 1

    return {"ip": ip, "pppoe_username": pppoe_username, "summary": summary, "class": cls}


# =========================================================
# CLI
# =========================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bulk runner for MikroTik CPE DNS Doctor (DB-backed).")

    p.add_argument("--mode", choices=["audit", "fix", "fix+reboot"], required=True)
    p.add_argument("--threads", type=int, default=30)

    p.add_argument("--city", action="append", default=None,
                   help="Radius city filter (can be repeated)")
    p.add_argument("--from-radius", action="store_true")
    p.add_argument("--all-cities", action="store_true")
    p.add_argument("--from-safe-list", dest="from_safe_list", type=str, default=None)
    p.add_argument("--input", type=str, default="targets.json")

    p.add_argument("--out-dir", type=str, default="out")
    p.add_argument("--limit", type=int, default=None, help="Limit targets (testing)")

    # batching + control
    p.add_argument("--batch-size", type=int, default=300,
                   help="Max in-flight tasks. Default=300")
    p.add_argument("--control-file", type=str, default=None,
                   help="Control JSON file for pause/resume/stop. Default: out/control_session_<id>.json")
    p.add_argument("--control-poll", type=float, default=1.0,
                   help="Control poll interval seconds. Default=1.0")

    # progress (web-ready fields are always written into summary json)
    p.add_argument("--progress", action="store_true",
                   help="Enable progress line in console.")
    p.add_argument("--progress-interval", type=float, default=2.0,
                   help="Progress refresh seconds (console). Default=2.0")

    # DB overrides
    p.add_argument("--db-host", type=str, default=None)
    p.add_argument("--db-port", type=int, default=None)
    p.add_argument("--db-user", type=str, default=None)
    p.add_argument("--db-pass", type=str, default=None)
    p.add_argument("--db-name", type=str, default=None)

    # main.py inputs
    p.add_argument("--telnet-user", type=str, default="admin")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--password", type=str, default=None)
    p.add_argument("--password-file", type=str, default=None)
    p.add_argument("--save-logs", action="store_true")

    # rules source passed to main.py
    p.add_argument("--rules-source", default="db", choices=["static", "db", "mixed"],
                   help="Rules source used by main.py. Default=db")

    return p


# =========================================================
# Progress Printer (timer + ETA + counters)
# =========================================================

def _make_progress_line(artifacts: Dict[str, Any], started_at_ts: float) -> str:
    stats = artifacts.get("stats", {})
    total = int(stats.get("total") or 0)
    done = int(stats.get("total_done") or 0)

    ok = int(stats.get("ok") or 0)
    warn = int(stats.get("warn") or 0)
    failed = int(stats.get("failed") or 0)
    fixed = int(stats.get("fixed") or 0)
    unreachable = int(stats.get("unreachable") or 0)

    login_failed = int(stats.get("login_failed") or 0)
    empty_pw = int(stats.get("empty_password") or 0)
    fix_applied = int(stats.get("fix_applied") or 0)
    rebooted = int(stats.get("rebooted") or 0)

    elapsed = time.time() - started_at_ts
    rate = (done / elapsed) if elapsed > 0 else 0.0
    remaining = max(0, total - done)
    eta = (remaining / rate) if rate > 0 else 0.0

    pct = (done * 100.0 / total) if total > 0 else 0.0

    return (
        f"[PROGRESS] {done}/{total} ({pct:.1f}%) | "
        f"ok={ok} warn={warn} fixed={fixed} failed={failed} unr={unreachable} | "
        f"loginFail={login_failed} emptyPw={empty_pw} fixApplied={fix_applied} rebooted={rebooted} | "
        f"rate={rate:.2f}/s | elapsed={fmt_hms(elapsed)} eta={fmt_hms(eta)}"
    )


def progress_thread_fn(
    stop_event: threading.Event,
    artifacts_lock: threading.Lock,
    artifacts: Dict[str, Any],
    started_at_ts: float,
    interval_s: float,
) -> None:
    while not stop_event.is_set():
        time.sleep(max(0.5, float(interval_s)))
        if stop_event.is_set():
            break
        with artifacts_lock:
            line = _make_progress_line(artifacts, started_at_ts)
        print(line)


# =========================================================
# Main runner
# =========================================================

def main() -> int:
    args = build_parser().parse_args()

    # -------- Targets source (DMA Radius / safe-list / file) --------
    radius_rows_count = 0
    radius_by_city_counts: Dict[str, int] = {}

    raw_cities: List[str] = []
    if isinstance(args.city, list):
        raw_cities = [c.strip() for c in args.city if c and str(c).strip()]
    elif isinstance(args.city, str) and args.city.strip():
        raw_cities = [args.city.strip()]

    if args.from_radius:
        if args.all_cities:
            cities = ["Zliten", "Khums", "Tarhuna", "Garabolly"]
        else:
            if not raw_cities:
                print("[ERROR] --from-radius requires --city (or use --all-cities).", file=sys.stderr)
                return 2
            cities = raw_cities

        rows = get_online_cpe_by_cities(cities)
        radius_rows_count = len(rows)

        for r in rows:
            c = str(r.get("city") or "UNKNOWN")
            radius_by_city_counts[c] = radius_by_city_counts.get(c, 0) + 1

        targets = [{"ip": r["cpe_ip"], "city": r.get("city"), "username": r.get("username")} for r in rows]
        targets = dedup_targets(targets)
        source_label = f"radius:{','.join(cities)}"

    elif args.from_safe_list:
        city_filter = raw_cities[0] if raw_cities else None
        if len(raw_cities) > 1:
            print("[WARN] Multiple --city values provided for file input; using first.", file=sys.stderr)
        targets = load_targets_from_file(args.from_safe_list, city_filter)
        source_label = f"safe_list:{args.from_safe_list}"

    else:
        city_filter = raw_cities[0] if raw_cities else None
        if len(raw_cities) > 1:
            print("[WARN] Multiple --city values provided for file input; using first.", file=sys.stderr)
        targets = load_targets_from_file(args.input, city_filter)
        source_label = f"input:{args.input}"

    if not targets:
        print(f"[ERROR] No targets found. Source={source_label}", file=sys.stderr)
        return 2

    # limit (after dedup)
    before_limit = len(targets)
    if args.limit is not None and args.limit > 0:
        targets = targets[:args.limit]
    after_limit = len(targets)

    # -------- DB init --------
    cfg = build_db_config(args)
    db = DBManager(cfg)

    # -------- Create session (web-ready meta) --------
    session_meta = {
        "source": source_label,
        "source_radius_rows": radius_rows_count,
        "source_radius_by_city_counts": radius_by_city_counts,
        "targets_total_before_limit": before_limit,
        "targets_total_after_limit": after_limit,
        "threads": args.threads,
        "batch_size": args.batch_size,
        "timeout": args.timeout,
        "limit": args.limit,
        "rules_source": args.rules_source,
        "telnet_user": args.telnet_user,
        "progress_enabled": bool(args.progress),
        "progress_interval": float(args.progress_interval),
        "cities": raw_cities,
    }

    session_city = None
    if args.from_radius:
        if args.all_cities:
            session_city = "ALL"
        else:
            session_city = ",".join(cities)
    else:
        session_city = raw_cities[0] if raw_cities else None

    session_id = db.create_scan_session(
        mode=args.mode,
        city=session_city,
        total_cpes=len(targets),
        status="running",
        meta=session_meta,
    )

    # -------- Console header (clear + detailed) --------
    print(f"[INFO] Session created: id={session_id}, mode={args.mode}, city={session_city}, targets={len(targets)}")
    print(f"[INFO] Targets source: {source_label}")
    if args.from_radius:
        print(f"[INFO] DMA Radius rows fetched: {radius_rows_count} | Unique IP targets: {before_limit} | Limit applied: {after_limit}")
        if radius_by_city_counts:
            city_str = ", ".join([f"{k}={v}" for k, v in sorted(radius_by_city_counts.items())])
            print(f"[INFO] DMA Radius by city: {city_str}")

    # -------- Control file --------
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    control_path = args.control_file or os.path.join(out_dir, f"control_session_{session_id}.json")
    control = ControlFile(control_path, poll_interval=float(args.control_poll))
    control.ensure_exists()
    print(f"[INFO] Control file: {control_path}")
    print('[INFO] To PAUSE: set {"pause": true}  | To RESUME: {"pause": false}  | To STOP: {"stop": true}')

    # -------- Artifacts (web-ready summary JSON) --------
    artifacts_lock = threading.Lock()
    artifacts: Dict[str, Any] = {
        "session_id": session_id,
        "mode": args.mode,
        "city": args.city,
        "rules_source": args.rules_source,
        "source": {
            "label": source_label,
            "radius_rows_count": radius_rows_count,
            "radius_by_city_counts": radius_by_city_counts,
            "targets_total_before_limit": before_limit,
            "targets_total_after_limit": after_limit,
        },
        "started_at": iso_now(),
        "finished_at": None,
        "elapsed_ms": None,
        "final_status": None,
        "stats": {
            "total": len(targets),
            "total_done": 0,
            # counters added dynamically: ok/warn/failed/fixed/unreachable/login_failed/empty_password/fix_applied/rebooted
        },
        "results": [],        # list of per-target summaries (web can page/filter)
        "warnings": {},       # ip -> warnings list
        "lists": {},          # status -> [ips]
    }

    # -------- main.py pass-through --------
    main_extra = {
        "telnet_user": args.telnet_user,
        "timeout": args.timeout,
        "password": args.password,
        "password_file": args.password_file,
        "save_logs": bool(args.save_logs),
        "rules_source": args.rules_source,
    }

    # -------- Runner state --------
    stop_event = threading.Event()
    started_at_ts = time.time()
    status_final = "completed"

    def finalize_session(final_status: str) -> None:
        nonlocal status_final
        status_final = final_status
        try:
            db.finish_scan_session(session_id=session_id, status=final_status)
        except Exception:
            pass

    def write_artifacts() -> None:
        elapsed_ms = int((time.time() - started_at_ts) * 1000)
        with artifacts_lock:
            artifacts["finished_at"] = iso_now()
            artifacts["elapsed_ms"] = elapsed_ms
            artifacts["final_status"] = status_final

        save_json(os.path.join(out_dir, f"session_{session_id}_results.json"), artifacts["results"])
        save_json(os.path.join(out_dir, f"session_{session_id}_warnings.json"), artifacts["warnings"])
        save_json(os.path.join(out_dir, f"session_{session_id}_lists.json"), artifacts["lists"])
        save_json(os.path.join(out_dir, f"session_{session_id}_summary.json"), artifacts)

        # Final console summary (clear)
        with artifacts_lock:
            print(f"[INFO] Artifacts written to: {out_dir}/session_{session_id}_*.json")
            print(f"[INFO] Final status: {status_final} | elapsed={fmt_hms(elapsed_ms/1000.0)}")
            print(f"[INFO] Final stats: {artifacts.get('stats')}")

    # -------- Optional progress thread --------
    prog_thread: Optional[threading.Thread] = None
    if args.progress:
        prog_thread = threading.Thread(
            target=progress_thread_fn,
            args=(stop_event, artifacts_lock, artifacts, started_at_ts, float(args.progress_interval)),
            daemon=True,
        )
        prog_thread.start()

    # -------- Execution with batching --------
    executor: Optional[ThreadPoolExecutor] = None
    futures: Dict[Future, Dict[str, Any]] = {}
    target_iter = iter(targets)

    try:
        executor = ThreadPoolExecutor(max_workers=args.threads)

        def submit_one(t: Dict[str, Any]) -> None:
            ip = str(t.get("ip") or "").strip()
            fut = executor.submit(
                worker_process_target,
                db, session_id, t, args.mode, main_extra,
                artifacts_lock, artifacts
            )
            futures[fut] = {"ip": ip, "target": t}

        while True:
            st = control.read_state()
            if st.stop:
                stop_event.set()
                reason = st.reason or "stop_requested"
                print(f"[WARN] STOP requested via control file. Reason={reason}")
                break

            control.wait_if_paused(stop_event)

            if stop_event.is_set():
                break

            while (not stop_event.is_set()) and (len(futures) < max(1, int(args.batch_size))):
                try:
                    t = next(target_iter)
                except StopIteration:
                    break
                submit_one(t)

            if not futures:
                break

            done_any = False
            for fut in list(futures.keys()):
                if fut.done():
                    done_any = True
                    meta = futures.pop(fut, None) or {}
                    ip = meta.get("ip")

                    try:
                        r = fut.result()
                        ip2 = r.get("ip", ip)
                        if r.get("skipped"):
                            # Keep it quiet unless needed
                            pass
                        else:
                            s = r.get("summary") or {}
                            status = str(s.get("status") or "unknown").lower()
                            warn_count = s.get("warning_count")
                            fix_applied = s.get("fix_applied")
                            # Minimal per-target line (progress thread is the main view)
                            if not args.progress:
                                print(f"[DONE] {ip2} status={status} warnings={warn_count} fix={fix_applied}")
                    except Exception as e:
                        if not args.progress:
                            print(f"[DONE] {ip} status=failed err={e}")
                    break

            if not done_any:
                time.sleep(0.05)

        if stop_event.is_set():
            finalize_session("canceled")
            return 130

        finalize_session("completed")
        return 0

    except KeyboardInterrupt:
        print("[WARN] Ctrl+C received. Canceling session...")
        stop_event.set()
        finalize_session("canceled")
        if executor:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
        return 130

    except Exception as e:
        print(f"[ERROR] Bulk run failed: {e}", file=sys.stderr)
        stop_event.set()
        finalize_session("failed")
        return 1

    finally:
        stop_event.set()
        if executor:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

        write_artifacts()


if __name__ == "__main__":
    raise SystemExit(main())
