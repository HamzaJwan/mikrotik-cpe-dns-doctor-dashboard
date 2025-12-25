# web/settings.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import os


# ------------------------------------------------------------
# Paths (resolved relative to project root)
# ------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = PROJECT_ROOT / "ui" / "templates"
STATIC_DIR = PROJECT_ROOT / "ui" / "static"

CONFIG_DIR = PROJECT_ROOT / "config"
PASSWORDS_FILE = CONFIG_DIR / "passwords.txt"

# ------------------------------------------------------------
# Database (used by web/api.py and ReportsDB fallback config)
# ------------------------------------------------------------
# These defaults are intentionally conservative and can be overridden by
# environment variables. This keeps Stage 1 read-only dashboard working
# out of the box, while remaining compatible with Stage 2/3.
DB_HOST: str = os.getenv("DB_HOST", "172.31.1.70")
DB_PORT: int = int(os.getenv("DB_PORT", "3309"))
DB_USER: str = os.getenv("DB_USER", "root")
DB_PASSWORD: str = os.getenv("DB_PASSWORD", "strongpass123")
DB_NAME: str = os.getenv("DB_NAME", "cpedoctor")

# Session cookie secret (set via env in production)
SESSION_SECRET: str = os.getenv("SESSION_SECRET", "dev-change-me")

# Diagnostic mode (exposes / OK page + /debug/paths)
DIAG_MODE: bool = str(os.getenv("DIAG_MODE", "0")).strip().lower() in ("1", "true", "yes", "on")


# ------------------------------------------------------------
# UI / Theme
# ------------------------------------------------------------
APP_TITLE = "MikroTik CPE DNS Doctor Dashboard"

# Dark blue + light grey (as requested)
THEME_PRIMARY = "#0B2A4A"   # dark blue
THEME_MUTED = "#F2F4F7"     # light grey
THEME_CARD = "#FFFFFF"
THEME_TEXT = "#111827"

# RTL mode default
DEFAULT_RTL = True

# Bootstrap 5 + RTL via CDN (no build tooling)
BOOTSTRAP_CSS_CDN = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
BOOTSTRAP_RTL_CSS_CDN = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css"
BOOTSTRAP_JS_CDN = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
BOOTSTRAP_ICONS_CDN = "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"

# Unified objects for templates (Jinja2 can access dict keys via dot)
THEME: dict = {
    "primary": THEME_PRIMARY,
    "muted": THEME_MUTED,
    "card": THEME_CARD,
    "text": THEME_TEXT,
}

CDN: dict = {
    "bootstrap_css": BOOTSTRAP_CSS_CDN,
    "bootstrap_rtl_css": BOOTSTRAP_RTL_CSS_CDN,
    "bootstrap_js": BOOTSTRAP_JS_CDN,
    "bootstrap_icons": BOOTSTRAP_ICONS_CDN,
}


# ------------------------------------------------------------
# Filters + Pagination defaults
# ------------------------------------------------------------
DEFAULT_SINCE_HOURS = 24
DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 200

PAGE_SIZE_OPTIONS: List[int] = [10, 20, 50, 100, 200]

# Sorting defaults (per-page tables)
DEFAULT_SORT = "id"
DEFAULT_SORT_DIR = "desc"


@dataclass
class Filters:
    # time filters
    since_hours: int = DEFAULT_SINCE_HOURS
    date_from: Optional[str] = None
    date_to: Optional[str] = None

    # common filters
    city: Optional[str] = None
    status: Optional[str] = None
    q: Optional[str] = None

    # pagination
    page: int = DEFAULT_PAGE
    page_size: int = DEFAULT_PAGE_SIZE

    # sorting
    sort: str = DEFAULT_SORT
    sort_dir: str = DEFAULT_SORT_DIR


def clamp_page_size(size: int) -> int:
    if size <= 0:
        return DEFAULT_PAGE_SIZE
    return min(size, MAX_PAGE_SIZE)


def normalize_sort_dir(v: str) -> str:
    v = (v or "").lower().strip()
    return "asc" if v == "asc" else "desc"


# ------------------------------------------------------------
# Stage 1 diagnostic hint (non-breaking)
# ------------------------------------------------------------
_WARNED_DB_PASSWORD_EMPTY = False
if DB_USER == "root" and (DB_PASSWORD is None or str(DB_PASSWORD) == ""):
    print(
        "[WARN] DB_PASSWORD is empty while DB_USER=root. "
        "If MySQL root has a password, set env var DB_PASSWORD before starting uvicorn."
    )

# ------------------------------------------------------------
# Patch: DB defaults should match core/db_manager.py (single source of truth)
# ------------------------------------------------------------
# Env vars override:
#   DB_HOST / DB_PORT / DB_USER / DB_PASSWORD / DB_NAME
# Optional (also supported by ReportsDB):
#   CPEDOCTOR_DB_HOST / CPEDOCTOR_DB_PORT / CPEDOCTOR_DB_USER / CPEDOCTOR_DB_PASSWORD / CPEDOCTOR_DB_NAME

try:
    from core.db_manager import DBConfig as CoreDBConfig  # type: ignore
    _core_cfg = CoreDBConfig()
except Exception:
    _core_cfg = None  # type: ignore

# Only set if not already defined above (backward compatible)
if "DB_HOST" not in globals():
    DB_HOST = os.getenv("DB_HOST", getattr(_core_cfg, "host", "127.0.0.1"))  # type: ignore
if "DB_PORT" not in globals():
    DB_PORT = int(os.getenv("DB_PORT", str(getattr(_core_cfg, "port", 3306))))  # type: ignore
if "DB_USER" not in globals():
    DB_USER = os.getenv("DB_USER", getattr(_core_cfg, "user", "root"))  # type: ignore
if "DB_PASSWORD" not in globals():
    DB_PASSWORD = os.getenv("DB_PASSWORD", getattr(_core_cfg, "password", ""))  # type: ignore
if "DB_NAME" not in globals():
    DB_NAME = os.getenv("DB_NAME", getattr(_core_cfg, "database", "cpedoctor"))  # type: ignore

# Ensure runtime env overrides always win
DB_HOST = os.getenv("DB_HOST", str(DB_HOST))  # type: ignore
DB_PORT = int(os.getenv("DB_PORT", str(DB_PORT)))  # type: ignore
DB_USER = os.getenv("DB_USER", str(DB_USER))  # type: ignore
DB_PASSWORD = os.getenv("DB_PASSWORD", str(DB_PASSWORD))  # type: ignore
DB_NAME = os.getenv("DB_NAME", str(DB_NAME))  # type: ignore

if DB_USER == "root" and (DB_PASSWORD or "").strip() == "" and not _WARNED_DB_PASSWORD_EMPTY:  # type: ignore
    _WARNED_DB_PASSWORD_EMPTY = True
    print("[WARN] DB_PASSWORD is empty while DB_USER=root. If MySQL root has a password, set env var DB_PASSWORD before starting uvicorn.")


# Optional Radius (DMA) DB overrides (used by core/radius_db.py if set)
RADIUS_DB_HOST = os.getenv('RADIUS_DB_HOST', '')
RADIUS_DB_PORT = int(os.getenv('RADIUS_DB_PORT', '3306')) if os.getenv('RADIUS_DB_PORT') else 3306
RADIUS_DB_USER = os.getenv('RADIUS_DB_USER', '')
RADIUS_DB_PASSWORD = os.getenv('RADIUS_DB_PASSWORD', '')
RADIUS_DB_NAME = os.getenv('RADIUS_DB_NAME', 'radius')
