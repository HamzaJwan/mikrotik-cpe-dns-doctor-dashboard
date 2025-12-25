# core/radius_db.py
"""
Radius DB Targets Provider
--------------------------
- Connects to Radius Manager DB (MariaDB/MySQL)
- Fetches ONLINE CPEs (radacct where acctstoptime IS NULL)
- Classifies city from rm_services.srvname prefix:
    Z% -> Zliten
    K% -> Khums
    T% -> Tarhuna
    G% -> Garabolly
- Returns: List[{"city":..., "username":..., "cpe_ip":...}]

Notes:
- Column name for IP in radacct is usually: framedipaddress
  If your DB uses a different column (e.g., framedip), set RADACCT_IP_COLUMN.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
import ipaddress
import os
import pymysql


# ----------------------------
# DB CONFIG (as you provided)
# ----------------------------

DB_CONFIG = {
    "host": os.getenv("RADIUS_DB_HOST", "172.31.1.71"),
    "port": int(os.getenv("RADIUS_DB_PORT", "3306")),
    "user": os.getenv("RADIUS_DB_USER", "wnetbackup"),
    "password": os.getenv("RADIUS_DB_PASSWORD", "wnet@1721811$Ww"),
    "db": os.getenv("RADIUS_DB_NAME", "radius"),
    "charset": os.getenv("RADIUS_DB_CHARSET", "utf8mb4"),
}

# If your radacct uses another column name for CPE IP, change here:
RADACCT_IP_COLUMN = "framedipaddress"   # or "framedip"


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def get_connection():
    """Return MariaDB connection using DictCursor + sensible timeouts."""
    return pymysql.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        db=DB_CONFIG["db"],
        charset=DB_CONFIG["charset"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=5,
        read_timeout=20,
        write_timeout=20,
    )


def get_online_cpe_by_cities(
    cities: List[str],
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch online CPE list filtered by cities.

    cities example:
        ["Zliten"] or ["Khums","Tarhuna"]

    Returns:
        [{"city":"Zliten","username":"...","cpe_ip":"10.x.x.x"}, ...]
    """
    if not cities:
        return []

    # Normalize city names (case-insensitive)
    wanted = [c.strip() for c in cities if c and c.strip()]
    if not wanted:
        return []

    ip_col = RADACCT_IP_COLUMN

    inner_sql = f"""
        SELECT
            CASE
                WHEN rs.srvname LIKE 'Z%%' THEN 'Zliten'
                WHEN rs.srvname LIKE 'K%%' THEN 'Khums'
                WHEN rs.srvname LIKE 'T%%' THEN 'Tarhuna'
                WHEN rs.srvname LIKE 'G%%' THEN 'Garabolly'
                ELSE 'Other Cities'
            END AS city,
            ra.username,
            ra.{ip_col} AS cpe_ip
        FROM radacct ra
        JOIN rm_users    ru ON ra.username = ru.username
        JOIN rm_services rs ON ru.srvid    = rs.srvid
        WHERE ra.acctstoptime IS NULL
    """

    placeholders = ",".join(["%s"] * len(wanted))
    final_sql = f"""
        SELECT city, username, cpe_ip
        FROM ({inner_sql}) AS sub
        WHERE city IN ({placeholders})
          AND cpe_ip IS NOT NULL
          AND cpe_ip <> ''
        ORDER BY city, username
    """

    if isinstance(limit, int) and limit > 0:
        final_sql += " LIMIT %s"
        params = wanted + [limit]
    else:
        params = wanted

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(final_sql, params)
            rows = cur.fetchall()
    finally:
        conn.close()

    # Filter invalid IPs + de-dup by IP (keep first occurrence)
    seen = set()
    out: List[Dict[str, Any]] = []
    for r in rows:
        ip = str(r.get("cpe_ip") or "").strip()
        if not ip or not _is_valid_ip(ip):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append({
            "city": r.get("city"),
            "username": r.get("username"),
            "cpe_ip": ip,
        })

    return out


def get_distinct_cities() -> List[str]:
    """
    Return distinct city names derived from DMA Radius online sessions.
    """
    ip_col = RADACCT_IP_COLUMN

    inner_sql = f"""
        SELECT
            CASE
                WHEN rs.srvname LIKE 'Z%%' THEN 'Zliten'
                WHEN rs.srvname LIKE 'K%%' THEN 'Khums'
                WHEN rs.srvname LIKE 'T%%' THEN 'Tarhuna'
                WHEN rs.srvname LIKE 'G%%' THEN 'Garabolly'
                ELSE 'Other Cities'
            END AS city,
            ra.{ip_col} AS cpe_ip
        FROM radacct ra
        JOIN rm_users    ru ON ra.username = ru.username
        JOIN rm_services rs ON ru.srvid    = rs.srvid
        WHERE ra.acctstoptime IS NULL
    """

    final_sql = f"""
        SELECT DISTINCT city
        FROM ({inner_sql}) AS sub
        WHERE city IS NOT NULL AND city <> ''
        ORDER BY city ASC
    """

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(final_sql)
            rows = cur.fetchall() or []
    except Exception:
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return [r.get("city") for r in rows if r.get("city")]
