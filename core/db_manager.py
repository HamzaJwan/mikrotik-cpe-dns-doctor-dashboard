# core/db_manager.py
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

import pymysql


# -----------------------------
# Exceptions
# -----------------------------

class DBError(Exception):
    pass


class IPAlreadyReserved(DBError):
    """Raised when the same IP is already reserved in the same scan session."""
    pass


# -----------------------------
# Config
# -----------------------------

@dataclass(frozen=True)
class DBConfig:
    host: str = "172.31.1.70"
    port: int = 3309
    user: str = "root"
    password: str = "strongpass123"
    database: str = "cpedoctor"

    charset: str = "utf8mb4"
    autocommit: bool = True

    # Safety defaults
    connect_timeout: int = 5
    read_timeout: int = 20
    write_timeout: int = 20


# -----------------------------
# DB Manager (with simple pool)
# -----------------------------

class DBManager:
    """
    Production-friendly MariaDB manager:
    - Ensures DB + schema exist on startup (auto bootstrap)
    - Thread-safe connections: each operation uses a pooled connection

    Identity model in your company:
    - PPPoE username is stable => inventory identity should be by pppoe_username.
    - IP is dynamic => store last_ip but do NOT treat it as the identity.

    Used by multi_cpe.py:
        create_scan_session(...)
        finish_scan_session(...)
        reserve_ip_once(...)
        upsert_inventory_latest_state(...)
        log_attempt(...)

    Added:
        report_*() helpers (DB-first, web-ready)
        IMPORTANT: reports JOIN logs -> cpe_inventory using cpe_id (primary) then ip fallback.
    """

    def __init__(self, config: Optional[DBConfig] = None, pool_size: int = 10):
        self.cfg = config or DBConfig()
        self.pool_size = max(2, int(pool_size))
        self._pool = []
        self._pool_lock = threading.Lock()

        # 1) Ensure database exists
        self._ensure_database()

        # 2) Ensure schema exists + migrations + seed rules
        self.ensure_schema()

    # -----------------------------
    # Connections / Pool
    # -----------------------------

    def _connect(self, use_db: bool = True):
        return pymysql.connect(
            host=self.cfg.host,
            port=self.cfg.port,
            user=self.cfg.user,
            password=self.cfg.password,
            db=self.cfg.database if use_db else None,
            charset=self.cfg.charset,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=self.cfg.autocommit,
            connect_timeout=self.cfg.connect_timeout,
            read_timeout=self.cfg.read_timeout,
            write_timeout=self.cfg.write_timeout,
        )

    def _get_conn(self):
        with self._pool_lock:
            if self._pool:
                return self._pool.pop()
        return self._connect(use_db=True)

    def _release_conn(self, conn):
        try:
            with self._pool_lock:
                if len(self._pool) < self.pool_size:
                    self._pool.append(conn)
                    return
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    def _execute(self, sql: str, params: Optional[tuple] = None, fetch: bool = False):
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params or ())
                if fetch:
                    return cur.fetchall()
                return cur.lastrowid
        finally:
            self._release_conn(conn)

    def _execute_one(self, sql: str, params: Optional[tuple] = None):
        rows = self._execute(sql, params=params, fetch=True)
        return rows[0] if rows else None

    # -----------------------------
    # JSON helpers
    # -----------------------------

    def _json(self, obj: Any) -> str:
        try:
            return json.dumps(obj, ensure_ascii=False)
        except Exception:
            return json.dumps({"_error": "json_serialize_failed"}, ensure_ascii=False)

    # -----------------------------
    # Auto DB + Schema
    # -----------------------------

    def _ensure_database(self):
        """
        Create the database if it doesn't exist.
        This requires user privileges (root usually has it).
        """
        conn = self._connect(use_db=False)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{self.cfg.database}` "
                    f"CHARACTER SET {self.cfg.charset} COLLATE {self.cfg.charset}_general_ci;"
                )
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def ensure_schema(self):
        """
        Create required tables if they don't exist.
        Then apply lightweight migrations safely.
        Safe to run on every startup.
        """
        # --- scan_sessions ---
        self._execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                status VARCHAR(32) NOT NULL,
                mode VARCHAR(32) NOT NULL,
                city VARCHAR(64) NULL,
                total_cpes INT NOT NULL DEFAULT 0,
                started_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
                finished_at DATETIME(3) NULL DEFAULT NULL,
                meta_json JSON NULL,
                PRIMARY KEY (id),
                KEY idx_scan_sessions_started_at (started_at),
                KEY idx_scan_sessions_status (status),
                KEY idx_scan_sessions_city (city)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # --- rules ---
        self._execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                check_command TEXT NOT NULL,
                warning_regex TEXT NOT NULL,
                fix_command TEXT NOT NULL,
                priority INT NOT NULL DEFAULT 100,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
                updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
                PRIMARY KEY (id),
                KEY idx_rules_active_priority (is_active, priority)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # --- cpe_inventory (latest state per USERNAME in your company) ---
        self._execute("""
            CREATE TABLE IF NOT EXISTS cpe_inventory (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

                -- dynamic
                last_ip VARCHAR(45) NOT NULL,

                -- stable identity (your case)
                pppoe_username VARCHAR(128) NULL,
                last_city VARCHAR(64) NULL,

                last_login_success TINYINT(1) NULL,
                last_password_used VARCHAR(255) NULL,
                last_password_is_empty TINYINT(1) NULL,

                last_status VARCHAR(64) NULL,
                last_fix_applied TINYINT(1) NULL,
                last_warning_count INT NOT NULL DEFAULT 0,

                last_session_id BIGINT UNSIGNED NULL,
                last_seen_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

                summary_json JSON NULL,
                warnings_json JSON NULL,

                PRIMARY KEY (id),
                UNIQUE KEY uq_cpe_inventory_last_ip (last_ip),
                KEY idx_cpe_inventory_city (last_city),
                KEY idx_cpe_inventory_last_seen (last_seen_at),
                KEY idx_cpe_inventory_session (last_session_id),
                KEY idx_cpe_inventory_user (pppoe_username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # --- logs (historical) ---
        self._execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                session_id BIGINT UNSIGNED NOT NULL,
                cpe_id BIGINT UNSIGNED NULL,

                ip VARCHAR(45) NOT NULL,
                action VARCHAR(32) NOT NULL,
                status VARCHAR(64) NOT NULL,

                login_success TINYINT(1) NULL,
                password_used VARCHAR(255) NULL,
                password_is_empty TINYINT(1) NULL,

                warning_count INT NOT NULL DEFAULT 0,
                fix_applied TINYINT(1) NULL,
                rebooted TINYINT(1) NULL,

                rules_result_json JSON NULL,
                raw_output_text MEDIUMTEXT NULL,

                created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

                PRIMARY KEY (id),
                UNIQUE KEY uq_logs_session_ip_action (session_id, ip, action),
                KEY idx_logs_ip_created (ip, created_at),
                KEY idx_logs_session (session_id),
                KEY idx_logs_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # Apply migrations (safe-ish)
        self._apply_migrations()

        # Seed baseline rules if empty
        self._seed_default_rules_if_empty()

    # -----------------------------
    # Migrations
    # -----------------------------

    def _apply_migrations(self) -> None:
        """
        Lightweight migrations to support:
        - inventory identity by pppoe_username (stable)
        - logs having optional pppoe_username/city (NOT required for reports, but helpful)
        """
        # 1) logs: add pppoe_username + city if missing (optional fields)
        self._alter_add_column_if_missing("logs", "pppoe_username", "VARCHAR(128) NULL")
        self._alter_add_column_if_missing("logs", "city", "VARCHAR(64) NULL")
        self._alter_add_column_if_missing("logs", "rebooted", "TINYINT(1) NULL")
        self._alter_add_index_if_missing("logs", "idx_logs_user_created", "(pppoe_username, created_at)")
        self._alter_add_index_if_missing("logs", "idx_logs_city_created", "(city, created_at)")
        self._alter_add_index_if_missing("logs", "idx_logs_cpe_created", "(cpe_id, created_at)")

        # 2) inventory: ensure unique on pppoe_username (identity)
        self._alter_add_unique_if_missing("cpe_inventory", "uq_cpe_inventory_user", "(pppoe_username)")

        # 3) Recommended: drop unique on last_ip (dynamic IPs)
        DROP_UNIQUE_LAST_IP = True
        if DROP_UNIQUE_LAST_IP:
            self._alter_drop_index_if_exists("cpe_inventory", "uq_cpe_inventory_last_ip")

    def _column_exists(self, table: str, column: str) -> bool:
        row = self._execute_one(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
            """,
            (self.cfg.database, table, column),
        )
        return bool(row and int(row["cnt"]) > 0)

    def _index_exists(self, table: str, index_name: str) -> bool:
        row = self._execute_one(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s
            """,
            (self.cfg.database, table, index_name),
        )
        return bool(row and int(row["cnt"]) > 0)

    def _alter_add_column_if_missing(self, table: str, column: str, ddl: str) -> None:
        if self._column_exists(table, column):
            return
        self._execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {ddl};")

    def _alter_add_index_if_missing(self, table: str, index_name: str, ddl_cols: str) -> None:
        if self._index_exists(table, index_name):
            return
        self._execute(f"ALTER TABLE `{table}` ADD INDEX `{index_name}` {ddl_cols};")

    def _alter_add_unique_if_missing(self, table: str, index_name: str, ddl_cols: str) -> None:
        if self._index_exists(table, index_name):
            return
        self._execute(f"ALTER TABLE `{table}` ADD UNIQUE INDEX `{index_name}` {ddl_cols};")

    def _alter_drop_index_if_exists(self, table: str, index_name: str) -> None:
        if not self._index_exists(table, index_name):
            return
        self._execute(f"ALTER TABLE `{table}` DROP INDEX `{index_name}`;")

    # -----------------------------
    # Seeding
    # -----------------------------

    def _seed_default_rules_if_empty(self):
        """
        If rules table is empty, insert 3 baseline rules.
        Safe to call on every startup.
        """
        row = self._execute_one("SELECT COUNT(*) AS cnt FROM rules;")
        if row and int(row["cnt"]) > 0:
            return

        seeds = [
            (
                "PPPoE use-peer-dns must be yes",
                "/interface pppoe-client print detail",
                r"use-peer-dns\s*[:=]\s*no",
                "/interface pppoe-client set [find] use-peer-dns=yes",
                10,
                1
            ),
            (
                "DNS allow-remote-requests must be yes",
                "/ip dns print",
                r"allow-remote-requests\s*[:=]\s*no",
                "/ip dns set allow-remote-requests=yes",
                20,
                1
            ),
            (
                "DHCP dns-server must use internal resolvers",
                "/ip dhcp-server network print",
                r"\b(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9|208\.67\.222\.222|208\.67\.220\.220)\b",
                '/ip dhcp-server network set [find] dns-server=""',
                30,
                1
            ),
        ]

        for seed in seeds:
            self._execute("""
                INSERT INTO rules (name, check_command, warning_regex, fix_command, priority, is_active)
                VALUES (%s, %s, %s, %s, %s, %s);
            """, seed)

    # -----------------------------
    # Public API used by multi_cpe
    # -----------------------------

    def get_active_rules(self):
        return self._execute(
            "SELECT * FROM rules WHERE is_active=1 ORDER BY priority ASC;",
            fetch=True
        )

    def create_scan_session(
        self,
        mode: str,
        city: Optional[str],
        total_cpes: int,
        status: str = "running",
        meta: Optional[Dict[str, Any]] = None,
    ) -> int:
        sql = """
            INSERT INTO scan_sessions (status, mode, city, total_cpes, meta_json)
            VALUES (%s, %s, %s, %s, %s);
        """
        return int(self._execute(sql, (status, mode, city, int(total_cpes), self._json(meta or {}))))

    def finish_scan_session(self, session_id: int, status: str = "completed") -> None:
        sql = """
            UPDATE scan_sessions
            SET status=%s, finished_at=CURRENT_TIMESTAMP(3)
            WHERE id=%s;
        """
        self._execute(sql, (status, int(session_id)))

    def reserve_ip_once(self, session_id: int, ip: str, action: str) -> None:
        """
        Prevent trying the same IP twice inside the same session.
        Implemented by inserting a unique (session_id, ip, action) record.
        """
        sql = """
            INSERT INTO logs (session_id, ip, action, status)
            VALUES (%s, %s, %s, %s);
        """
        try:
            self._execute(sql, (int(session_id), ip, action, "reserved"))
        except pymysql.err.IntegrityError:
            raise IPAlreadyReserved(f"Already reserved in this session: session={session_id} ip={ip} action={action}")

    def upsert_inventory_latest_state(
        self,
        ip: str,
        pppoe_username: Optional[str],
        city: Optional[str],
        last_login_success: Optional[bool],
        password_used: Optional[str],
        password_is_empty: Optional[bool],
        last_status: str,
        last_fix_applied: Optional[bool],
        last_warning_count: int,
        last_session_id: int,
        last_seen_at,
        summary: Optional[Dict[str, Any]] = None,
        warnings: Any = None,
    ) -> int:
        """
        Inventory upsert policy:
        - If pppoe_username is present (stable identity), upsert by username.
        - Else fallback to ip (rare/UNKNOWN usernames).
        """
        pppoe_username_norm = (pppoe_username or "").strip() or None

        if pppoe_username_norm:
            sql = """
                INSERT INTO cpe_inventory (
                    pppoe_username,
                    last_ip, last_city,
                    last_login_success, last_password_used, last_password_is_empty,
                    last_status, last_fix_applied, last_warning_count,
                    last_session_id, last_seen_at,
                    summary_json, warnings_json
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    last_ip=VALUES(last_ip),
                    last_city=VALUES(last_city),
                    last_login_success=VALUES(last_login_success),
                    last_password_used=VALUES(last_password_used),
                    last_password_is_empty=VALUES(last_password_is_empty),
                    last_status=VALUES(last_status),
                    last_fix_applied=VALUES(last_fix_applied),
                    last_warning_count=VALUES(last_warning_count),
                    last_session_id=VALUES(last_session_id),
                    last_seen_at=VALUES(last_seen_at),
                    summary_json=VALUES(summary_json),
                    warnings_json=VALUES(warnings_json);
            """

            self._execute(sql, (
                pppoe_username_norm,
                ip, city,
                self._to_bool(last_login_success), password_used, self._to_bool(password_is_empty),
                last_status, self._to_bool(last_fix_applied), int(last_warning_count or 0),
                int(last_session_id), last_seen_at,
                self._json(summary or {}), self._json(warnings),
            ))

            row = self._execute_one("SELECT id FROM cpe_inventory WHERE pppoe_username=%s;", (pppoe_username_norm,))
            return int(row["id"]) if row else 0

        # Fallback: by IP (unknown username)
        sql = """
            INSERT INTO cpe_inventory (
                last_ip, pppoe_username, last_city,
                last_login_success, last_password_used, last_password_is_empty,
                last_status, last_fix_applied, last_warning_count,
                last_session_id, last_seen_at,
                summary_json, warnings_json
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                pppoe_username=VALUES(pppoe_username),
                last_city=VALUES(last_city),
                last_login_success=VALUES(last_login_success),
                last_password_used=VALUES(last_password_used),
                last_password_is_empty=VALUES(last_password_is_empty),
                last_status=VALUES(last_status),
                last_fix_applied=VALUES(last_fix_applied),
                last_warning_count=VALUES(last_warning_count),
                last_session_id=VALUES(last_session_id),
                last_seen_at=VALUES(last_seen_at),
                summary_json=VALUES(summary_json),
                warnings_json=VALUES(warnings_json);
        """

        self._execute(sql, (
            ip, pppoe_username, city,
            self._to_bool(last_login_success), password_used, self._to_bool(password_is_empty),
            last_status, self._to_bool(last_fix_applied), int(last_warning_count or 0),
            int(last_session_id), last_seen_at,
            self._json(summary or {}), self._json(warnings)
        ))

        row = self._execute_one("SELECT id FROM cpe_inventory WHERE last_ip=%s;", (ip,))
        return int(row["id"]) if row else 0

    def log_attempt(
        self,
        session_id: int,
        ip: str,
        action: str,
        status: str,
        login_success: Optional[bool] = None,
        password_used: Optional[str] = None,
        password_is_empty: Optional[bool] = None,
        warning_count: int = 0,
        fix_applied: Optional[bool] = None,
        rebooted: Optional[bool] = None,
        rules_result: Any = None,
        raw_output_text: Optional[str] = None,
        cpe_id: Optional[int] = None,
        pppoe_username: Optional[str] = None,
        city: Optional[str] = None,
    ) -> None:
        """
        Update the reserved row (created in reserve_ip_once) to a final log entry.
        Uses UPSERT with unique key (session_id, ip, action).
        """
        sql = """
            INSERT INTO logs (
                session_id, cpe_id, ip, action, status,
                login_success, password_used, password_is_empty,
                warning_count, fix_applied, rebooted,
                rules_result_json, raw_output_text,
                pppoe_username, city
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                cpe_id=VALUES(cpe_id),
                status=VALUES(status),
                login_success=VALUES(login_success),
                password_used=VALUES(password_used),
                password_is_empty=VALUES(password_is_empty),
                warning_count=VALUES(warning_count),
                fix_applied=VALUES(fix_applied),
                rebooted=VALUES(rebooted),
                rules_result_json=VALUES(rules_result_json),
                raw_output_text=VALUES(raw_output_text),
                pppoe_username=VALUES(pppoe_username),
                city=VALUES(city);
        """
        self._execute(sql, (
            int(session_id), int(cpe_id) if cpe_id else None,
            ip, action, status,
            self._to_bool(login_success), password_used, self._to_bool(password_is_empty),
            int(warning_count or 0), self._to_bool(fix_applied), self._to_bool(rebooted),
            self._json(rules_result), raw_output_text,
            (pppoe_username or None), (city or None),
        ))

    # -----------------------------
    # Reporting API (DB-first, web-ready)
    # -----------------------------

    def _time_filter(self, since_hours: Optional[int]) -> Tuple[str, tuple]:
        if since_hours is None:
            return "", ()
        return " AND l.created_at >= (NOW(3) - INTERVAL %s HOUR) ", (int(since_hours),)

    def get_last_session_id(self) -> Optional[int]:
        row = self._execute_one("SELECT id FROM scan_sessions ORDER BY id DESC LIMIT 1;")
        return int(row["id"]) if row else None

    # ---- Inventory: latest status by username (best for dashboard) ----

    def report_inventory_status(
        self,
        city: Optional[str] = None,
        status: Optional[str] = None,
        login_success: Optional[bool] = None,
        limit: int = 5000
    ) -> List[Dict[str, Any]]:
        where = ["pppoe_username IS NOT NULL"]
        params: List[Any] = []

        if city:
            where.append("last_city = %s")
            params.append(city)
        if status:
            where.append("last_status = %s")
            params.append(status)
        if login_success is not None:
            where.append("last_login_success = %s")
            params.append(1 if login_success else 0)

        sql = f"""
            SELECT
                pppoe_username,
                last_ip,
                last_city,
                last_status,
                last_login_success,
                last_password_is_empty,
                last_warning_count,
                last_fix_applied,
                last_session_id,
                last_seen_at
            FROM cpe_inventory
            WHERE {" AND ".join(where)}
            ORDER BY last_seen_at DESC
            LIMIT %s;
        """
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    def report_inventory_needs_manual(
        self,
        city: Optional[str] = None,
        limit: int = 2000
    ) -> List[Dict[str, Any]]:
        """
        Users that likely need manual intervention:
        - login failed OR empty password used OR status=failed
        """
        where = [
            "pppoe_username IS NOT NULL",
            "(last_login_success = 0 OR last_password_is_empty = 1 OR last_status = 'failed')"
        ]
        params: List[Any] = []
        if city:
            where.append("last_city=%s")
            params.append(city)

        sql = f"""
            SELECT
                pppoe_username,
                last_ip,
                last_city,
                last_status,
                last_login_success,
                last_password_is_empty,
                last_warning_count,
                last_seen_at
            FROM cpe_inventory
            WHERE {" AND ".join(where)}
            ORDER BY last_seen_at DESC
            LIMIT %s;
        """
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    # ---- Logs: session/time-window reports (JOIN inventory for accurate username/city) ----

    def _logs_join_inventory_from(self) -> str:
        """
        Canonical FROM/JOIN used by reports:
        - Primary: join by cpe_id (best, created by upsert_inventory_latest_state)
        - Fallback: join by last_ip == logs.ip (helps older rows / edge cases)
        """
        return """
            FROM logs l
            LEFT JOIN cpe_inventory ci
              ON (ci.id = l.cpe_id) OR (ci.last_ip = l.ip)
        """

    def report_login_failed_users(
        self,
        session_id: Optional[int] = None,
        since_hours: Optional[int] = 24,
        limit: int = 2000
    ) -> List[Dict[str, Any]]:
        t_sql, t_params = self._time_filter(since_hours)

        where = ["(l.login_success = 0 OR l.status = 'failed')"]
        params: List[Any] = []

        if session_id is not None:
            where.append("l.session_id=%s")
            params.append(int(session_id))

        sql = f"""
            SELECT
                COALESCE(ci.pppoe_username, l.pppoe_username, 'UNKNOWN') AS pppoe_username,
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                l.ip,
                l.action,
                l.status,
                l.created_at
            {self._logs_join_inventory_from()}
            WHERE {" AND ".join(where)}
            {t_sql}
            ORDER BY l.created_at DESC
            LIMIT %s;
        """
        params.extend(list(t_params))
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    def report_empty_password_users(
        self,
        session_id: Optional[int] = None,
        since_hours: Optional[int] = 24,
        limit: int = 2000
    ) -> List[Dict[str, Any]]:
        t_sql, t_params = self._time_filter(since_hours)

        where = ["l.password_is_empty = 1"]
        params: List[Any] = []

        if session_id is not None:
            where.append("l.session_id=%s")
            params.append(int(session_id))

        sql = f"""
            SELECT
                COALESCE(ci.pppoe_username, l.pppoe_username, 'UNKNOWN') AS pppoe_username,
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                l.ip,
                l.action,
                l.status,
                l.created_at
            {self._logs_join_inventory_from()}
            WHERE {" AND ".join(where)}
            {t_sql}
            ORDER BY l.created_at DESC
            LIMIT %s;
        """
        params.extend(list(t_params))
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    def report_warn_users(
        self,
        session_id: Optional[int] = None,
        since_hours: Optional[int] = 24,
        min_warnings: int = 1,
        limit: int = 5000
    ) -> List[Dict[str, Any]]:
        t_sql, t_params = self._time_filter(since_hours)

        where = ["l.warning_count >= %s"]
        params: List[Any] = [int(min_warnings)]

        if session_id is not None:
            where.append("l.session_id=%s")
            params.append(int(session_id))

        sql = f"""
            SELECT
                COALESCE(ci.pppoe_username, l.pppoe_username, 'UNKNOWN') AS pppoe_username,
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                l.ip,
                l.action,
                l.status,
                l.warning_count,
                l.fix_applied,
                l.created_at
            {self._logs_join_inventory_from()}
            WHERE {" AND ".join(where)}
            {t_sql}
            ORDER BY l.warning_count DESC, l.created_at DESC
            LIMIT %s;
        """
        params.extend(list(t_params))
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    def report_fixed_users(
        self,
        session_id: Optional[int] = None,
        since_hours: Optional[int] = 24,
        limit: int = 5000
    ) -> List[Dict[str, Any]]:
        t_sql, t_params = self._time_filter(since_hours)

        where = ["l.fix_applied = 1"]
        params: List[Any] = []

        if session_id is not None:
            where.append("l.session_id=%s")
            params.append(int(session_id))

        sql = f"""
            SELECT
                COALESCE(ci.pppoe_username, l.pppoe_username, 'UNKNOWN') AS pppoe_username,
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                l.ip,
                l.action,
                l.status,
                l.warning_count,
                l.created_at
            {self._logs_join_inventory_from()}
            WHERE {" AND ".join(where)}
            {t_sql}
            ORDER BY l.created_at DESC
            LIMIT %s;
        """
        params.extend(list(t_params))
        params.append(int(limit))
        return self._execute(sql, tuple(params), fetch=True)

    def report_city_summary(
        self,
        session_id: Optional[int] = None,
        since_hours: Optional[int] = 24
    ) -> List[Dict[str, Any]]:
        """
        KPI summary per city (JOIN inventory):
        - total
        - failed logins
        - empty password
        - warned
        - fixed
        """
        t_sql, t_params = self._time_filter(since_hours)

        where = ["1=1"]
        params: List[Any] = []

        if session_id is not None:
            where.append("l.session_id=%s")
            params.append(int(session_id))

        sql = f"""
            SELECT
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                COUNT(*) AS total_rows,
                SUM(CASE WHEN (l.login_success=0 OR l.status='failed') THEN 1 ELSE 0 END) AS login_failed,
                SUM(CASE WHEN l.password_is_empty=1 THEN 1 ELSE 0 END) AS empty_password,
                SUM(CASE WHEN l.warning_count>0 THEN 1 ELSE 0 END) AS warned,
                SUM(CASE WHEN l.fix_applied=1 THEN 1 ELSE 0 END) AS fixed
            {self._logs_join_inventory_from()}
            WHERE {" AND ".join(where)}
            {t_sql}
            GROUP BY COALESCE(ci.last_city, l.city, 'UNKNOWN')
            ORDER BY total_rows DESC;
        """
        params.extend(list(t_params))
        return self._execute(sql, tuple(params), fetch=True)
    
    # داخل class DBManager في core/db_manager.py

    def report_dashboard_kpis(
        self,
        since_hours: Optional[int] = 24,
        city: Optional[str] = None,
        status: Optional[str] = None,
        q: Optional[str] = None,  # search username/ip
    ) -> Dict[str, Any]:
        where = ["pppoe_username IS NOT NULL"]
        params: List[Any] = []

        if since_hours is not None:
            where.append("last_seen_at >= (NOW(3) - INTERVAL %s HOUR)")
            params.append(int(since_hours))

        if city:
            where.append("last_city = %s")
            params.append(city)

        if status:
            where.append("last_status = %s")
            params.append(status)

        if q:
            q = str(q).strip()
            if q:
                where.append("(pppoe_username LIKE %s OR last_ip LIKE %s)")
                params.extend([f"%{q}%", f"%{q}%"])

        sql = f"""
            SELECT
                COUNT(*) AS total_targets,
                SUM(CASE WHEN last_status='ok' THEN 1 ELSE 0 END) AS ok_count,
                SUM(CASE WHEN (last_status='failed') THEN 1 ELSE 0 END) AS failed_count,
                SUM(CASE WHEN (last_login_success=0) THEN 1 ELSE 0 END) AS login_failed_count,
                SUM(CASE WHEN (last_fix_applied=1) THEN 1 ELSE 0 END) AS fix_applied_count,
                SUM(CASE WHEN (last_warning_count>0) THEN 1 ELSE 0 END) AS warned_count
            FROM cpe_inventory
            WHERE {" AND ".join(where)};
        """
        row = self._execute_one(sql, tuple(params)) or {}

        # Last finished session duration (seconds)
        last_run = self._execute_one("""
            SELECT
                id,
                started_at,
                finished_at,
                TIMESTAMPDIFF(SECOND, started_at, finished_at) AS duration_s
            FROM scan_sessions
            WHERE finished_at IS NOT NULL
            ORDER BY id DESC
            LIMIT 1;
        """) or {}

        # Stage 1 placeholders (to be wired in Stage 2/3)
        rebooted_count = 0

        return {
            "total_targets": int(row.get("total_targets") or 0),
            "ok": int(row.get("ok_count") or 0),
            "failed": int(row.get("failed_count") or 0),
            "login_failed": int(row.get("login_failed_count") or 0),
            "fix_applied": int(row.get("fix_applied_count") or 0),
            "warned": int(row.get("warned_count") or 0),
            "rebooted": int(rebooted_count),
            "last_run_duration_s": int(last_run.get("duration_s") or 0),
            "last_run_session_id": (int(last_run["id"]) if last_run.get("id") is not None else None),
        }

    def report_recent_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        sql = """
            SELECT
                id,
                mode,
                city,
                targets_count,
                started_at,
                finished_at,
                TIMESTAMPDIFF(SECOND, started_at, finished_at) AS duration_s
            FROM scan_sessions
            ORDER BY id DESC
            LIMIT %s;
        """
        return self._execute(sql, (int(limit),), fetch=True)

    def report_distinct_cities(self, limit: int = 200) -> List[str]:
        rows = self._execute("""
            SELECT DISTINCT last_city AS city
            FROM cpe_inventory
            WHERE last_city IS NOT NULL AND last_city <> ''
            ORDER BY last_city ASC
            LIMIT %s;
        """, (int(limit),), fetch=True)
        return [str(r["city"]) for r in (rows or []) if r.get("city")]

    def report_session_overview(self, session_id: int) -> Dict[str, Any]:
        """
        One object overview for a session (for CLI + future web).
        """
        sid = int(session_id)

        totals = self._execute_one(f"""
            SELECT
                COUNT(*) AS total_rows,
                SUM(CASE WHEN (l.login_success=0 OR l.status='failed') THEN 1 ELSE 0 END) AS login_failed,
                SUM(CASE WHEN l.password_is_empty=1 THEN 1 ELSE 0 END) AS empty_password,
                SUM(CASE WHEN l.warning_count>0 THEN 1 ELSE 0 END) AS warned,
                SUM(CASE WHEN l.fix_applied=1 THEN 1 ELSE 0 END) AS fixed
            {self._logs_join_inventory_from()}
            WHERE l.session_id=%s;
        """, (sid,)) or {}

        top_warn = self._execute(f"""
            SELECT
                COALESCE(ci.pppoe_username, l.pppoe_username, 'UNKNOWN') AS pppoe_username,
                COALESCE(ci.last_city, l.city, 'UNKNOWN') AS city,
                l.ip,
                l.action,
                l.warning_count,
                l.status,
                l.created_at
            {self._logs_join_inventory_from()}
            WHERE l.session_id=%s AND l.warning_count>0
            ORDER BY l.warning_count DESC, l.created_at DESC
            LIMIT 50;
        """, (sid,), fetch=True)

        return {
            "session_id": sid,
            "totals": totals,
            "top_warn": top_warn,
            "by_city": self.report_city_summary(session_id=sid, since_hours=None),
        }

    # -----------------------------
    # utils
    # -----------------------------

    @staticmethod
    def _to_bool(v):
        if v is None:
            return None
        return 1 if bool(v) else 0
