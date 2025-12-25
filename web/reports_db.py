# web/reports_db.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import os
import json
import pymysql
import pymysql.cursors


# -----------------------------
# DB Config
# -----------------------------
@dataclass(frozen=True)
class DBConfig:
    host: str
    port: int
    user: str
    password: str
    db: str

    @staticmethod
    def from_env() -> "DBConfig":
        host = os.getenv("DB_HOST", "172.31.1.70")
        port = int(os.getenv("DB_PORT", "3309"))
        user = os.getenv("DB_USER", "root")
        password = os.getenv("DB_PASSWORD", "strongpass123")
        db = os.getenv("DB_NAME", "cpedoctor")
        return DBConfig(host=host, port=port, user=user, password=password, db=db)


def _to_int(v: Any, default: Optional[int] = None) -> Optional[int]:
    if v is None:
        return default
    try:
        s = str(v).strip()
        if s == "":
            return default
        return int(s)
    except Exception:
        return default


def _like(v: str) -> str:
    return f"%{v}%"


def _safe_sort_dir(v: Optional[str]) -> str:
    if not v:
        return "desc"
    v = v.strip().lower()
    return "asc" if v == "asc" else "desc"

# Status buckets:
# - ok: ok
# - warn: warn (must NOT be counted as failed)
# - fixed: fixed
# - failed: failed + unreachable (if present)
FAILED_STATUSES = ("failed", "unreachable")
DEFAULT_STATUSES = [
    "ok",
    "warn",
    "fixed",
    "failed",
    "unreachable",
    "login_failed",
    "reserved",
    "running",
    "completed",
    "stopped",
    "cancelled",
]


def _normalize_filter_list(filters: Dict[str, Any], list_key: str, single_key: str) -> List[str]:
    values: List[str] = []
    raw = filters.get(list_key)
    if isinstance(raw, (list, tuple)):
        values = list(raw)
    elif isinstance(raw, str) and raw.strip():
        values = [raw]

    if not values:
        raw_single = filters.get(single_key)
        if isinstance(raw_single, (list, tuple)):
            values = list(raw_single)
        elif isinstance(raw_single, str) and raw_single.strip():
            values = raw_single.split(",")

    out: List[str] = []
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        out.append(s)
    return out


def _get_cities(filters: Dict[str, Any]) -> List[str]:
    return _normalize_filter_list(filters, "cities", "city")


def _get_statuses(filters: Dict[str, Any]) -> List[str]:
    raw = _normalize_filter_list(filters, "statuses", "status")
    out: List[str] = []
    for v in raw:
        s = str(v).strip().lower()
        if not s or s == "all":
            continue
        if s not in out:
            out.append(s)
    if "failed" in out and "unreachable" in out:
        out = [v for v in out if v != "unreachable"]
    return out


def _build_in_clause(column: str, values: List[str], params: List[Any]) -> Optional[str]:
    if not values:
        return None
    placeholders = ", ".join(["%s"] * len(values))
    params.extend(values)
    return f"{column} IN ({placeholders})"


def _build_status_where(
    status_col: str,
    login_col: Optional[str],
    statuses: List[str],
    params: List[Any],
) -> Optional[str]:
    if not statuses:
        return None
    parts: List[str] = []
    for st in statuses:
        if st == "failed":
            parts.append(f"{status_col} IN (%s, %s)")
            params.extend(list(FAILED_STATUSES))
        elif st == "login_failed" and login_col:
            parts.append(f"({status_col} = 'login_failed' OR {login_col} = 0)")
        else:
            parts.append(f"{status_col} = %s")
            params.append(st)
    if not parts:
        return None
    return "(" + " OR ".join(parts) + ")"


def _coalesce_hours(filters: Dict[str, Any]) -> int:
    """
    If no time filter is provided at all, default to 24h to keep queries bounded.
    """
    since_hours = _to_int(filters.get("since_hours"), None)
    date_from = (filters.get("date_from") or "").strip()
    date_to = (filters.get("date_to") or "").strip()

    if since_hours is None and not date_from and not date_to:
        return 24
    return since_hours or 0


def _build_time_where(
    column: str,
    filters: Dict[str, Any],
    params: List[Any],
) -> str:
    """
    Builds time window WHERE part based on:
      - since_hours (NOW() - INTERVAL ? HOUR)
      - date_from (>= date_from 00:00:00)
      - date_to   (<  date_to + 1 day)
    """
    parts: List[str] = []

    since_hours = _to_int(filters.get("since_hours"), None)
    date_from = (filters.get("date_from") or "").strip()
    date_to = (filters.get("date_to") or "").strip()

    # Default to 24h if nothing provided
    if since_hours is None and not date_from and not date_to:
        since_hours = 24

    if since_hours is not None:
        parts.append(f"{column} >= (NOW() - INTERVAL %s HOUR)")
        params.append(since_hours)

    if date_from:
        parts.append(f"{column} >= %s")
        params.append(f"{date_from} 00:00:00")

    if date_to:
        parts.append(f"{column} < (DATE_ADD(%s, INTERVAL 1 DAY))")
        params.append(f"{date_to} 00:00:00")

    if not parts:
        return "1=1"

    return "(" + " AND ".join(parts) + ")"


# -----------------------------
# ReportsDB
# -----------------------------
class ReportsDB:
    """
    Read-only reporting layer for Stage 1.
    Uses your actual schema (core/db_manager.py):
      - cpe_inventory(pppoe_username, last_ip, last_city, last_status, last_login_success, last_fix_applied, last_warning_count, last_seen_at, ...)
      - logs(created_at, pppoe_username, ip, city, status, warning_count, login_success, fix_applied, session_id, ...)
      - scan_sessions(id, status, mode, city, total_cpes, started_at, finished_at, meta_json, ...)
    """

    def __init__(
        self,
        cfg: Optional[DBConfig] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        db: Optional[str] = None,
    ):
        if cfg is not None:
            self.cfg = cfg
            return

        base = DBConfig.from_env()
        db_name = database if database is not None else db

        self.cfg = DBConfig(
            host=host or base.host,
            port=int(port) if port is not None else base.port,
            user=user or base.user,
            password=(password if password is not None else base.password),
            db=db_name or base.db,
        )

    def _connect(self):
        return pymysql.connect(
            host=self.cfg.host,
            port=self.cfg.port,
            user=self.cfg.user,
            password=self.cfg.password,
            database=self.cfg.db,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=3,
            read_timeout=3,
            write_timeout=3,
        )

    def _fetchone(self, sql: str, params: List[Any] | Tuple[Any, ...] = ()):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchone()

    def _fetchall(self, sql: str, params: List[Any] | Tuple[Any, ...] = ()):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()

    def _table_columns(self, table: str) -> set[str]:
        if not hasattr(self, "_columns_cache"):
            self._columns_cache = {}
        cache: Dict[str, set[str]] = self._columns_cache  # type: ignore[attr-defined]
        if table in cache:
            return cache[table]
        cols: set[str] = set()
        try:
            rows = self._fetchall(f"SHOW COLUMNS FROM {table}") or []
            cols = {str(r.get("Field")) for r in rows if r.get("Field")}
        except Exception:
            cols = set()
        cache[table] = cols
        return cols

    def _has_column(self, table: str, column: str) -> bool:
        return column in self._table_columns(table)

    def _username_expr_parts(self, alias: str, table: str) -> List[str]:
        parts: List[str] = []
        if self._has_column(table, "pppoe_username"):
            parts.append(f"NULLIF({alias}.pppoe_username, '')")
        if self._has_column(table, "radius_username"):
            parts.append(f"NULLIF({alias}.radius_username, '')")
        if self._has_column(table, "username"):
            parts.append(f"NULLIF({alias}.username, '')")
        return parts

    def _coalesce_expr(self, parts: List[str], include_unknown: bool = True) -> str:
        if not parts:
            return "'UNKNOWN'" if include_unknown else "NULL"
        expr = "COALESCE(" + ", ".join(parts) + ")"
        if include_unknown:
            expr = f"COALESCE({expr}, 'UNKNOWN')"
        return expr

    # -----------------------------
    # Health
    # -----------------------------
    def healthcheck(self) -> Dict[str, Any]:
        row = self._fetchone("SELECT 1 AS ok")
        return {"ok": bool(row and row.get("ok") == 1), "db": self.cfg.db, "host": self.cfg.host, "port": self.cfg.port}

    # -----------------------------
    # Dashboard KPIs (from cpe_inventory)
    # -----------------------------
    def dashboard_kpis(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        params: List[Any] = []
        where_parts: List[str] = []

        where_parts.append(_build_time_where("ci.last_seen_at", filters, params))

        cities = _get_cities(filters)
        city_clause = _build_in_clause("ci.last_city", cities, params)
        if city_clause:
            where_parts.append(city_clause)

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("ci.last_status", "ci.last_login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(self._username_expr_parts("ci", "cpe_inventory"), include_unknown=False)
            where_parts.append(f"({user_expr} LIKE %s OR ci.last_ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"

        sql = f"""
        SELECT
            COUNT(*) AS total_targets,
            SUM(CASE WHEN last_status = 'ok' THEN 1 ELSE 0 END) AS ok_count,
            SUM(CASE WHEN last_status = 'warn' THEN 1 ELSE 0 END) AS warn_count,
            SUM(CASE WHEN last_status = 'fixed' THEN 1 ELSE 0 END) AS fixed_count,
            SUM(CASE WHEN last_status IN ('failed', 'unreachable') THEN 1 ELSE 0 END) AS failed_count,
            SUM(CASE WHEN last_status = 'unreachable' THEN 1 ELSE 0 END) AS unreachable_count,
            SUM(CASE WHEN (last_status = 'login_failed' OR last_login_success = 0) THEN 1 ELSE 0 END) AS login_failed_count,
            SUM(CASE WHEN last_fix_applied = 1 THEN 1 ELSE 0 END) AS fix_applied_count
        FROM cpe_inventory ci
        WHERE {where_sql}
        """
        row = self._fetchone(sql, params) or {}

        return {
            "total_targets": int(row.get("total_targets") or 0),
            "ok": int(row.get("ok_count") or 0),
            "warn": int(row.get("warn_count") or 0),
            "fixed": int(row.get("fixed_count") or 0),
            "failed": int(row.get("failed_count") or 0),
            "unreachable": int(row.get("unreachable_count") or 0),
            "login_failed": int(row.get("login_failed_count") or 0),
            "fix_applied": int(row.get("fix_applied_count") or 0),
            "rebooted": 0,
        }

    # -----------------------------
    # Sessions (ROOT FIX): derive from logs.session_id
    # -----------------------------
    def sessions_count(self, filters: Dict[str, Any]) -> int:
        params: List[Any] = []
        where_parts: List[str] = ["l.session_id IS NOT NULL"]

        # time based on logs.created_at (this is the important fix)
        where_parts.append(_build_time_where("l.created_at", filters, params))

        cities = _get_cities(filters)
        if cities:
            placeholders = ", ".join(["%s"] * len(cities))
            where_parts.append(f"(s.city IN ({placeholders}) OR l.city IN ({placeholders}))")
            params.extend(cities)
            params.extend(cities)

        statuses = _get_statuses(filters)
        if statuses:
            placeholders = ", ".join(["%s"] * len(statuses))
            where_parts.append(f"(COALESCE(s.status,'') IN ({placeholders}))")
            params.extend(statuses)

        q = (filters.get("q") or "").strip()
        if q:
            where_parts.append("(CAST(l.session_id AS CHAR) LIKE %s)")
            params.append(_like(q))

        where_sql = " AND ".join(where_parts)

        sql = f"""
        SELECT COUNT(*) AS c
        FROM (
            SELECT l.session_id
            FROM logs l
            LEFT JOIN scan_sessions s ON s.id = l.session_id
            WHERE {where_sql}
            GROUP BY l.session_id
        ) t
        """
        row = self._fetchone(sql, params) or {}
        return int(row.get("c") or 0)

    def sessions_list(self, filters: Dict[str, Any], limit: int, offset: int) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where_parts: List[str] = ["l.session_id IS NOT NULL"]

        where_parts.append(_build_time_where("l.created_at", filters, params))

        cities = _get_cities(filters)
        if cities:
            placeholders = ", ".join(["%s"] * len(cities))
            where_parts.append(f"(s.city IN ({placeholders}) OR l.city IN ({placeholders}))")
            params.extend(cities)
            params.extend(cities)

        statuses = _get_statuses(filters)
        if statuses:
            placeholders = ", ".join(["%s"] * len(statuses))
            where_parts.append(f"(COALESCE(s.status,'') IN ({placeholders}))")
            params.extend(statuses)

        q = (filters.get("q") or "").strip()
        if q:
            where_parts.append("(CAST(l.session_id AS CHAR) LIKE %s)")
            params.append(_like(q))

        where_sql = " AND ".join(where_parts)

        # sorting (optional)
        sort_key = (filters.get("sort") or "").strip().lower()
        sort_dir = _safe_sort_dir(filters.get("sort_dir"))
        allowed_sort = {
            "id": "id",
            "started": "started_at",
            "finished": "finished_at",
            "total": "total_cpes",
            "city": "city",
            "mode": "mode",
            "status": "status",
        }
        order_col = allowed_sort.get(sort_key, "started_at")

        sql = f"""
        SELECT
            l.session_id AS id,
            COALESCE(s.status, 'unknown') AS status,
            COALESCE(s.mode, 'unknown') AS mode,
            COALESCE(s.city, MAX(l.city)) AS city,
            MIN(l.created_at) AS started_at,
            MAX(l.created_at) AS finished_at,
            COUNT(DISTINCT l.ip) AS total_cpes
        FROM logs l
        LEFT JOIN scan_sessions s ON s.id = l.session_id
        WHERE {where_sql}
        GROUP BY l.session_id, s.status, s.mode, s.city
        ORDER BY {order_col} {sort_dir}
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        return self._fetchall(sql, params) or []

    def latest_sessions(self, filters: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
        # clone filters but ensure bounded time window
        f = dict(filters)
        if not f.get("since_hours") and not f.get("date_from") and not f.get("date_to"):
            f["since_hours"] = 24
        return self.sessions_list(f, limit=limit, offset=0)

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        # prefer scan_sessions row if exists
        srow = self._fetchone(
            """
            SELECT id, status, mode, city, total_cpes, started_at, finished_at, meta_json
            FROM scan_sessions
            WHERE id = %s
            """,
            (session_id,),
        )

        # derive from logs (always)
        lrow = self._fetchone(
            """
            SELECT
                MIN(created_at) AS started_at,
                MAX(created_at) AS finished_at,
                COUNT(DISTINCT ip) AS total_cpes,
                SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_count,
                SUM(CASE WHEN status='warn' THEN 1 ELSE 0 END) AS warn_count,
                SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) AS fixed_count,
                SUM(CASE WHEN status IN ('failed','unreachable') THEN 1 ELSE 0 END) AS failed_count,
                SUM(CASE WHEN status='unreachable' THEN 1 ELSE 0 END) AS unreachable_count,
                SUM(CASE WHEN (status='login_failed' OR login_success=0) THEN 1 ELSE 0 END) AS login_failed_count,
                SUM(CASE WHEN fix_applied=1 THEN 1 ELSE 0 END) AS fix_applied_count
            FROM logs
            WHERE session_id = %s
            """,
            (session_id,),
        ) or {}

        if not srow and not lrow.get("started_at"):
            return None

        out: Dict[str, Any] = {
            "id": session_id,
            "status": (srow or {}).get("status", "unknown"),
            "mode": (srow or {}).get("mode", "unknown"),
            "city": (srow or {}).get("city", None),
            "total_cpes": int((srow or {}).get("total_cpes") or (lrow.get("total_cpes") or 0)),
            "started_at": (srow or {}).get("started_at") or lrow.get("started_at"),
            "finished_at": (srow or {}).get("finished_at") or lrow.get("finished_at"),
            "kpis": {
                "ok": int(lrow.get("ok_count") or 0),
                "warn": int(lrow.get("warn_count") or 0),
                "fixed": int(lrow.get("fixed_count") or 0),
                "failed": int(lrow.get("failed_count") or 0),
                "unreachable": int(lrow.get("unreachable_count") or 0),
                "login_failed": int(lrow.get("login_failed_count") or 0),
                "fix_applied": int(lrow.get("fix_applied_count") or 0),
                "rebooted": 0,
            },
            "summary": None,
        }

        if srow and srow.get("meta_json"):
            try:
                out["summary"] = json.loads(srow["meta_json"])
            except Exception:
                out["summary"] = srow["meta_json"]

        return out

    # Backward-compatible aliases used by web/api.py
    def session_get(self, session_id: int) -> Optional[Dict[str, Any]]:
        return self.get_session(session_id)

    def session_outcomes_count(self, session_id: int, filters: Dict[str, Any]) -> int:
        return self.session_rows_count(session_id, filters)

    def session_outcomes_list(
        self,
        session_id: int,
        filters: Dict[str, Any],
        limit: int,
        offset: int,
    ) -> List[Dict[str, Any]]:
        return self.session_rows_list(session_id, filters, limit, offset)

    def session_rows_count(self, session_id: int, filters: Dict[str, Any]) -> int:
        params: List[Any] = [session_id]
        where_parts: List[str] = ["session_id = %s"]
        # optional time filter on created_at
        where_parts.append(_build_time_where("created_at", filters, params))

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(self._username_expr_parts("l", "logs"), include_unknown=False)
            where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts)
        row = self._fetchone(f"SELECT COUNT(*) AS c FROM logs l WHERE {where_sql}", params) or {}
        return int(row.get("c") or 0)

    def session_rows_list(self, session_id: int, filters: Dict[str, Any], limit: int, offset: int) -> List[Dict[str, Any]]:
        params: List[Any] = [session_id]
        where_parts: List[str] = ["session_id = %s"]
        where_parts.append(_build_time_where("created_at", filters, params))

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(self._username_expr_parts("l", "logs"), include_unknown=False)
            where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts)

        sort_dir = _safe_sort_dir(filters.get("sort_dir"))

        sql = f"""
        SELECT
            created_at,
            pppoe_username,
            ip,
            city,
            action,
            status,
            warning_count,
            login_success,
            fix_applied
        FROM logs l
        WHERE {where_sql}
        ORDER BY created_at {sort_dir}
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        return self._fetchall(sql, params) or []

    # -----------------------------
    # Inventory (from cpe_inventory)
    # -----------------------------
    def inventory_count(self, filters: Dict[str, Any]) -> int:
        params: List[Any] = []
        where_parts: List[str] = []

        where_parts.append(_build_time_where("ci.last_seen_at", filters, params))

        cities = _get_cities(filters)
        city_clause = _build_in_clause("ci.last_city", cities, params)
        if city_clause:
            where_parts.append(city_clause)

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("ci.last_status", "ci.last_login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(self._username_expr_parts("ci", "cpe_inventory"), include_unknown=False)
            where_parts.append(f"({user_expr} LIKE %s OR ci.last_ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"
        row = self._fetchone(f"SELECT COUNT(*) AS c FROM cpe_inventory ci WHERE {where_sql}", params) or {}
        return int(row.get("c") or 0)

    def inventory_list(self, filters: Dict[str, Any], limit: int, offset: int) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where_parts: List[str] = []

        where_parts.append(_build_time_where("ci.last_seen_at", filters, params))

        cities = _get_cities(filters)
        city_clause = _build_in_clause("ci.last_city", cities, params)
        if city_clause:
            where_parts.append(city_clause)

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("ci.last_status", "ci.last_login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(self._username_expr_parts("ci", "cpe_inventory"), include_unknown=False)
            where_parts.append(f"({user_expr} LIKE %s OR ci.last_ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"

        sort_key = (filters.get("sort") or "").strip().lower()
        sort_dir = _safe_sort_dir(filters.get("sort_dir"))
        allowed_sort = {
            "username": "canonical_username",
            "ip": "last_ip",
            "city": "last_city",
            "status": "last_status",
            "seen": "last_seen_at",
        }
        order_col = allowed_sort.get(sort_key, "last_seen_at")

        sql = f"""
        SELECT
            {self._coalesce_expr(self._username_expr_parts("ci", "cpe_inventory"), include_unknown=True)} AS canonical_username,
            ci.pppoe_username,
            ci.last_ip,
            ci.last_city,
            ci.last_status,
            ci.last_login_success,
            ci.last_fix_applied,
            ci.last_seen_at
        FROM cpe_inventory ci
        WHERE {where_sql}
        ORDER BY {order_col} {sort_dir}
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        return self._fetchall(sql, params) or []

    # -----------------------------
    # Inventory History (from logs)
    # -----------------------------
    def inventory_history_count(self, filters: Dict[str, Any]) -> int:
        params: List[Any] = []
        where_parts: List[str] = []
        where_parts.append(_build_time_where("l.created_at", filters, params))

        cities = _get_cities(filters)
        city_clause = _build_in_clause("l.city", cities, params)
        if city_clause:
            where_parts.append(city_clause)

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(
                self._username_expr_parts("i", "cpe_inventory") + self._username_expr_parts("l", "logs"),
                include_unknown=False,
            )
            where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"
        row = self._fetchone(
            f"""
            SELECT COUNT(*) AS c
            FROM logs l
            LEFT JOIN cpe_inventory i ON i.id = l.cpe_id
            WHERE {where_sql}
            """,
            params,
        ) or {}
        return int(row.get("c") or 0)

    def inventory_history_list(self, filters: Dict[str, Any], limit: int, offset: int) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where_parts: List[str] = []
        where_parts.append(_build_time_where("l.created_at", filters, params))

        cities = _get_cities(filters)
        city_clause = _build_in_clause("l.city", cities, params)
        if city_clause:
            where_parts.append(city_clause)

        statuses = _get_statuses(filters)
        status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
        if status_clause:
            where_parts.append(status_clause)

        q = (filters.get("q") or "").strip()
        if q:
            user_expr = self._coalesce_expr(
                self._username_expr_parts("i", "cpe_inventory") + self._username_expr_parts("l", "logs"),
                include_unknown=False,
            )
            where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
            params.extend([_like(q), _like(q)])

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"
        sort_dir = _safe_sort_dir(filters.get("sort_dir"))

        sql = f"""
        SELECT
            l.created_at,
            {self._coalesce_expr(self._username_expr_parts("i", "cpe_inventory") + self._username_expr_parts("l", "logs"), include_unknown=True)} AS canonical_username,
            l.pppoe_username,
            l.ip,
            l.city,
            l.status,
            l.warning_count,
            l.login_success,
            l.fix_applied,
            l.session_id
        FROM logs l
        LEFT JOIN cpe_inventory i ON i.id = l.cpe_id
        WHERE {where_sql}
        ORDER BY l.created_at {sort_dir}
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        return self._fetchall(sql, params) or []

    # -----------------------------
    # Reports (Stage 1 basic set)
    # -----------------------------
    def reports_list(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return [
            {"key": "login_failed", "title": "Login Failed", "description": "كل المحاولات التي فشل فيها تسجيل الدخول ضمن الفترة المحددة."},
            {"key": "fix_applied", "title": "Fix Applied", "description": "السجلات التي تم فيها تطبيق إصلاح."},
            {"key": "rebooted", "title": "Rebooted", "description": "السجلات التي تم فيها تنفيذ reboot."},
            {"key": "top_failing_ips", "title": "Top Failing IPs", "description": "أكثر IPs فشلت (حسب عدد السجلات غير OK)."},
        ]

    def report_rows_count(self, report_key: str, filters: Dict[str, Any]) -> int:
        sql, params = self._report_sql(report_key, filters, count_only=True, limit=0, offset=0)
        row = self._fetchone(sql, params) or {}
        return int(row.get("c") or 0)

    def report_rows(
        self,
        report_key: str,
        filters: Dict[str, Any],
        sort_key: Optional[str] = None,
        sort_dir: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        sql, params, columns = self._report_sql(
            report_key,
            filters,
            count_only=False,
            limit=limit,
            offset=offset,
            sort_key=sort_key,
            sort_dir=sort_dir,
        )
        rows = self._fetchall(sql, params) or []
        return rows, columns

    def _report_sql(
        self,
        report_key: str,
        filters: Dict[str, Any],
        count_only: bool,
        limit: int,
        offset: int,
        sort_key: Optional[str] = None,
        sort_dir: Optional[str] = None,
    ):
        """
        Returns:
          - if count_only: (sql, params)
          - else: (sql, params, columns)
        """
        params: List[Any] = []
        time_where = _build_time_where("l.created_at", filters, params)

        cities = _get_cities(filters)
        statuses = _get_statuses(filters)
        q = (filters.get("q") or "").strip()

        if report_key == "login_failed":
            where_parts = [time_where, "(l.status = 'login_failed' OR l.login_success = 0)"]
            city_clause = _build_in_clause("l.city", cities, params)
            if city_clause:
                where_parts.append(city_clause)
            status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
            if status_clause:
                where_parts.append(status_clause)
            if q:
                user_expr = self._coalesce_expr(self._username_expr_parts("l", "logs"), include_unknown=False)
                where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
                params.extend([_like(q), _like(q)])

            where_sql = " AND ".join(where_parts)

            if count_only:
                return (f"SELECT COUNT(*) AS c FROM logs l WHERE {where_sql}", params)

            columns = [
                {"key": "created_at", "label": "Time"},
                {"key": "pppoe_username", "label": "Username"},
                {"key": "ip", "label": "IP"},
                {"key": "city", "label": "City"},
                {"key": "status", "label": "Status"},
                {"key": "warning_count", "label": "Warnings"},
                {"key": "session_id", "label": "Session"},
            ]
            allowed_sort = {
                "created_at": "created_at",
                "pppoe_username": "pppoe_username",
                "ip": "ip",
                "city": "city",
                "status": "status",
                "warning_count": "warning_count",
                "session_id": "session_id",
            }
            order_col = allowed_sort.get(sort_key or "", "created_at")
            sql = f"""
            SELECT created_at, pppoe_username, ip, city, status, warning_count, session_id
            FROM logs l
            WHERE {where_sql}
            ORDER BY {order_col} {sort_dir}
            LIMIT %s OFFSET %s
            """
            params2 = list(params) + [limit, offset]
            return (sql, params2, columns)

        if report_key == "fix_applied":
            where_parts = [time_where, "(l.fix_applied = 1 OR l.status = 'fixed')"]
            city_clause = _build_in_clause("l.city", cities, params)
            if city_clause:
                where_parts.append(city_clause)
            status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
            if status_clause:
                where_parts.append(status_clause)
            if q:
                user_expr = self._coalesce_expr(self._username_expr_parts("l", "logs"), include_unknown=False)
                where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
                params.extend([_like(q), _like(q)])

            where_sql = " AND ".join(where_parts)

            if count_only:
                return (f"SELECT COUNT(*) AS c FROM logs l WHERE {where_sql}", params)

            columns = [
                {"key": "created_at", "label": "Time"},
                {"key": "pppoe_username", "label": "Username"},
                {"key": "ip", "label": "IP"},
                {"key": "city", "label": "City"},
                {"key": "status", "label": "Status"},
                {"key": "rebooted", "label": "Rebooted"},
                {"key": "session_id", "label": "Session"},
            ]
            allowed_sort = {
                "created_at": "created_at",
                "pppoe_username": "pppoe_username",
                "ip": "ip",
                "city": "city",
                "status": "status",
                "rebooted": "rebooted",
                "session_id": "session_id",
            }
            order_col = allowed_sort.get(sort_key or "", "created_at")
            sql = f"""
            SELECT created_at, pppoe_username, ip, city, status, rebooted, session_id
            FROM logs l
            WHERE {where_sql}
            ORDER BY {order_col} {sort_dir}
            LIMIT %s OFFSET %s
            """
            params2 = list(params) + [limit, offset]
            return (sql, params2, columns)

        if report_key == "rebooted":
            reboot_clause = "l.rebooted = 1"
            if self._has_column("logs", "reboot_requested"):
                reboot_clause = "(l.rebooted = 1 OR l.reboot_requested = 1)"
            where_parts = [time_where, reboot_clause]
            city_clause = _build_in_clause("l.city", cities, params)
            if city_clause:
                where_parts.append(city_clause)
            status_clause = _build_status_where("l.status", "l.login_success", statuses, params)
            if status_clause:
                where_parts.append(status_clause)
            if q:
                user_expr = self._coalesce_expr(self._username_expr_parts("l", "logs"), include_unknown=False)
                where_parts.append(f"({user_expr} LIKE %s OR l.ip LIKE %s)")
                params.extend([_like(q), _like(q)])

            where_sql = " AND ".join(where_parts)

            if count_only:
                return (f"SELECT COUNT(*) AS c FROM logs l WHERE {where_sql}", params)

            columns = [
                {"key": "created_at", "label": "Time"},
                {"key": "pppoe_username", "label": "Username"},
                {"key": "ip", "label": "IP"},
                {"key": "city", "label": "City"},
                {"key": "status", "label": "Status"},
                {"key": "fix_applied", "label": "Fix"},
                {"key": "session_id", "label": "Session"},
            ]
            allowed_sort = {
                "created_at": "created_at",
                "pppoe_username": "pppoe_username",
                "ip": "ip",
                "city": "city",
                "status": "status",
                "fix_applied": "fix_applied",
                "session_id": "session_id",
            }
            order_col = allowed_sort.get(sort_key or "", "created_at")
            sql = f"""
            SELECT created_at, pppoe_username, ip, city, status, fix_applied, session_id
            FROM logs l
            WHERE {where_sql}
            ORDER BY {order_col} {sort_dir}
            LIMIT %s OFFSET %s
            """
            params2 = list(params) + [limit, offset]
            return (sql, params2, columns)

        if report_key == "top_failing_ips":
            fail_statuses = ["failed", "unreachable", "login_failed"]
            if statuses:
                fail_statuses = [s for s in fail_statuses if s in statuses]
            if not fail_statuses:
                where_parts = [time_where, "1=0"]
            else:
                placeholders = ", ".join(["%s"] * len(fail_statuses))
                params.extend(fail_statuses)
                include_login_failed = (not statuses) or ("login_failed" in statuses)
                status_clause = f"l.status IN ({placeholders})"
                if include_login_failed:
                    status_clause = f"({status_clause} OR l.login_success = 0)"
                where_parts = [time_where, status_clause]

            city_clause = _build_in_clause("l.city", cities, params)
            if city_clause:
                where_parts.append(city_clause)
            if q:
                where_parts.append("(l.ip LIKE %s)")
                params.append(_like(q))

            where_sql = " AND ".join(where_parts)

            if count_only:
                return (
                    f"""
                    SELECT COUNT(*) AS c FROM (
                        SELECT ip
                        FROM logs l
                        WHERE {where_sql}
                        GROUP BY ip
                    ) t
                    """,
                    params,
                )

            columns = [
                {"key": "ip", "label": "IP"},
                {"key": "city", "label": "City"},
                {"key": "fail_count", "label": "Failures"},
                {"key": "last_seen", "label": "Last Seen"},
            ]
            allowed_sort = {
                "ip": "ip",
                "city": "city",
                "fail_count": "fail_count",
                "last_seen": "last_seen",
            }
            order_col = allowed_sort.get(sort_key or "", "fail_count")
            sql = f"""
            SELECT
                ip,
                MAX(city) AS city,
                COUNT(*) AS fail_count,
                MAX(created_at) AS last_seen
            FROM logs l
            WHERE {where_sql}
            GROUP BY ip
            ORDER BY {order_col} {sort_dir}
            LIMIT %s OFFSET %s
            """
            params2 = list(params) + [limit, offset]
            return (sql, params2, columns)

        # unknown report key -> empty
        if count_only:
            return ("SELECT 0 AS c", [])
        return ("SELECT 1 WHERE 0", [], [{"key": "n/a", "label": "n/a"}])


    # -----------------------------
    # Stage 2: Rules (CRUD)
    # -----------------------------
    def rules_list(self) -> List[Dict[str, Any]]:
        sql = """
        SELECT
            id, name, priority, is_active,
            check_command, warning_regex, fix_command,
            created_at, updated_at
        FROM rules
        ORDER BY priority ASC, id ASC
        """
        return list(self._fetchall(sql) or [])

    def get_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        sql = """
        SELECT
            id, name, priority, is_active,
            check_command, warning_regex, fix_command,
            created_at, updated_at
        FROM rules
        WHERE id=%s
        """
        return self._fetchone(sql, (int(rule_id),))

    def create_rule(
        self,
        name: str,
        priority: int,
        is_active: bool,
        check_command: str,
        warning_regex: str,
        fix_command: Optional[str],
    ) -> int:
        sql = """
        INSERT INTO rules (name, priority, is_active, check_command, warning_regex, fix_command)
        VALUES (%s,%s,%s,%s,%s,%s)
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    (name or "").strip(),
                    int(priority or 0),
                    1 if is_active else 0,
                    (check_command or "").strip(),
                    (warning_regex or "").strip(),
                    (fix_command or None),
                ))
                conn.commit()
                return int(cur.lastrowid or 0)

    def update_rule(
        self,
        rule_id: int,
        name: str,
        priority: int,
        is_active: bool,
        check_command: str,
        warning_regex: str,
        fix_command: Optional[str],
    ) -> None:
        sql = """
        UPDATE rules
        SET
            name=%s,
            priority=%s,
            is_active=%s,
            check_command=%s,
            warning_regex=%s,
            fix_command=%s,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=%s
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    (name or "").strip(),
                    int(priority or 0),
                    1 if is_active else 0,
                    (check_command or "").strip(),
                    (warning_regex or "").strip(),
                    (fix_command or None),
                    int(rule_id),
                ))
                conn.commit()

    def toggle_rule(self, rule_id: int) -> None:
        sql = """
        UPDATE rules
        SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=%s
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (int(rule_id),))
                conn.commit()

    def delete_rule(self, rule_id: int) -> None:
        sql = "DELETE FROM rules WHERE id=%s"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (int(rule_id),))
                conn.commit()

    # -----------------------------
    # Stage 3: Run control helpers
    # -----------------------------
    def distinct_cities(self) -> List[str]:
        sql = """
        SELECT DISTINCT last_city AS city
        FROM cpe_inventory
        WHERE last_city IS NOT NULL AND last_city <> ''
        ORDER BY city ASC
        """
        rows = self._fetchall(sql) or []
        return [r.get("city") for r in rows if r.get("city")]

    def filter_options(self) -> Dict[str, List[str]]:
        cities: set[str] = set()
        statuses: set[str] = set([s for s in DEFAULT_STATUSES])

        try:
            rows = self._fetchall(
                """
                SELECT DISTINCT last_city AS city
                FROM cpe_inventory
                WHERE last_city IS NOT NULL AND last_city <> ''
                """
            ) or []
            for r in rows:
                v = (r.get("city") or "").strip()
                if v:
                    cities.add(v)
        except Exception:
            pass

        try:
            rows = self._fetchall(
                """
                SELECT DISTINCT city
                FROM logs
                WHERE city IS NOT NULL AND city <> ''
                """
            ) or []
            for r in rows:
                v = (r.get("city") or "").strip()
                if v:
                    cities.add(v)
        except Exception:
            pass

        try:
            rows = self._fetchall(
                """
                SELECT DISTINCT last_status AS status
                FROM cpe_inventory
                WHERE last_status IS NOT NULL AND last_status <> ''
                """
            ) or []
            for r in rows:
                v = (r.get("status") or "").strip().lower()
                if v:
                    statuses.add(v)
        except Exception:
            pass

        try:
            rows = self._fetchall(
                """
                SELECT DISTINCT status
                FROM logs
                WHERE status IS NOT NULL AND status <> ''
                """
            ) or []
            for r in rows:
                v = (r.get("status") or "").strip().lower()
                if v:
                    statuses.add(v)
        except Exception:
            pass

        return {
            "cities": sorted(cities, key=str.lower),
            "statuses": sorted(statuses),
        }

    def session_progress(
        self,
        session_id: int,
        include_rows: bool = False,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 25,
        offset: int = 0,
    ) -> Dict[str, Any]:
        # total targets from scan_sessions (fallback to logs count)
        sess = self._fetchone("SELECT id, status, mode, city, total_cpes, started_at, finished_at FROM scan_sessions WHERE id=%s", (int(session_id),)) or {}
        total = int(sess.get("total_cpes") or 0)

        sql = """
        SELECT status, COUNT(*) AS c
        FROM logs
        WHERE session_id=%s
        GROUP BY status
        """
        rows = self._fetchall(sql, (int(session_id),)) or []
        by_status = {(r.get("status") or "unknown"): int(r.get("c") or 0) for r in rows}

        summary = self._fetchone(
            """
            SELECT
                MAX(created_at) AS last_updated,
                SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_count,
                SUM(CASE WHEN status='warn' THEN 1 ELSE 0 END) AS warn_count,
                SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) AS fixed_count,
                SUM(CASE WHEN status IN ('failed','unreachable') THEN 1 ELSE 0 END) AS failed_count,
                SUM(CASE WHEN status='unreachable' THEN 1 ELSE 0 END) AS unreachable_count,
                SUM(CASE WHEN (status='login_failed' OR login_success=0) THEN 1 ELSE 0 END) AS login_failed_count,
                SUM(CASE WHEN fix_applied=1 THEN 1 ELSE 0 END) AS fix_applied_count,
                SUM(CASE WHEN rebooted=1 THEN 1 ELSE 0 END) AS rebooted_count
            FROM logs
            WHERE session_id=%s
            """,
            (int(session_id),),
        ) or {}

        processed = sum(v for k, v in by_status.items() if str(k).lower() != "reserved")
        reserved = int(by_status.get("reserved", 0))

        if total <= 0:
            total = processed + reserved

        pct = 0.0
        if total > 0:
            pct = round((processed / total) * 100.0, 2)

        out = {
            "session": sess,
            "total": total,
            "processed": processed,
            "reserved": reserved,
            "by_status": by_status,
            "percent": pct,
            "kpis": {
                "ok": int(summary.get("ok_count") or 0),
                "warn": int(summary.get("warn_count") or 0),
                "fixed": int(summary.get("fixed_count") or 0),
                "failed": int(summary.get("failed_count") or 0),
                "unreachable": int(summary.get("unreachable_count") or 0),
                "login_failed": int(summary.get("login_failed_count") or 0),
                "fix_applied": int(summary.get("fix_applied_count") or 0),
                "rebooted": int(summary.get("rebooted_count") or 0),
            },
            "last_updated": summary.get("last_updated"),
        }

        if include_rows:
            f = filters or {}
            lim = max(1, int(limit or 25))
            off = max(0, int(offset or 0))
            out["rows"] = self.session_rows_list(session_id, f, lim, off)

        return out
