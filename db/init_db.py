#!/usr/bin/env python

import os
import sys
from pathlib import Path

import pymysql


def env(name: str, default: str = "") -> str:
    v = os.getenv(name, default)
    return v if v is not None else default


def main() -> int:
    host = env("DB_HOST", "172.31.1.70")
    port = int(env("DB_PORT", "3309"))
    user = env("DB_USER", "root")
    password = env("DB_PASSWORD", "strongpass123")
    db = env("DB_NAME", "cpedoctor")

    schema_path = Path(__file__).resolve().parent / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")

    print(f"[INIT] Connecting to {user}@{host}:{port}/{db}")
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db,
        charset="utf8mb4",
        autocommit=False,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with conn.cursor() as cur:
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                cur.execute(stmt)
        conn.commit()
        print("[INIT] Schema applied successfully.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
