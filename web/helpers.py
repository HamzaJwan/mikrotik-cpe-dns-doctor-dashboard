from __future__ import annotations

import math
import re
from typing import Dict, Any, Optional, List, Iterable


def _to_int(v: Optional[str], default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def normalize_sort_dir(value: Optional[str], default: str = "desc") -> str:
    """
    Normalize sort direction.
    Accepts: asc, desc (case-insensitive), also supports aliases: up/down, 1/-1
    Returns only: 'asc' or 'desc'
    """
    v = (value or "").strip().lower()

    if v in ("asc", "a", "up", "1", "+1", "true", "yes"):
        return "asc"
    if v in ("desc", "d", "down", "-1", "false", "no"):
        return "desc"

    d = (default or "desc").strip().lower()
    return "asc" if d == "asc" else "desc"


def normalize_sort_field(value: Optional[str], allowed: Iterable[str], default: Optional[str] = None) -> Optional[str]:
    """
    Normalize sort field by allow-list.
    Returns the field if allowed, otherwise default.
    """
    v = (value or "").strip()
    if not v:
        return default
    allowed_set = set([str(x) for x in allowed])
    return v if v in allowed_set else default


def normalize_sort_key(
    value: Optional[str],
    allowed: Optional[Iterable[str]] = None,
    default: Optional[str] = None,
) -> Optional[str]:
    """
    Normalize sort key (column name) safely.

    - Trims whitespace
    - Allows only [a-zA-Z0-9_]
    - Optional allow-list validation
    """
    v = (value or "").strip()
    if not v:
        return default

    # Basic safety: only simple identifiers
    if not re.match(r"^[A-Za-z0-9_]+$", v):
        return default

    if allowed is not None:
        allowed_set = set([str(x) for x in allowed])
        return v if v in allowed_set else default

    return v


def _split_csv_values(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        if v is None:
            continue
        parts = [p.strip() for p in str(v).split(",") if p.strip()]
        out.extend(parts)
    return out


def parse_filters(
    request,
    default_page: int = 1,
    default_page_size: int = 25,
) -> Dict[str, Any]:
    qp = request.query_params

    page = _to_int(qp.get("page"), default_page)
    page_size = _to_int(qp.get("page_size"), default_page_size)

    # Safety clamps
    page = max(1, page)
    page_size = max(1, min(500, page_size))

    cities = _split_csv_values(qp.getlist("city"))
    statuses = _split_csv_values(qp.getlist("status"))

    f = {
        "q": (qp.get("q") or "").strip() or None,
        "city": (",".join(cities) if cities else (qp.get("city") or "").strip() or None),
        "status": (",".join(statuses) if statuses else (qp.get("status") or "").strip() or None),
        "cities": cities,
        "statuses": statuses,
        "mode": (qp.get("mode") or "").strip() or None,
        "since_hours": (qp.get("since_hours") or "").strip() or None,
        "date_from": (qp.get("date_from") or "").strip() or None,
        "date_to": (qp.get("date_to") or "").strip() or None,
        "page": page,
        "page_size": page_size,
        # sort_key is the canonical key used by /reports/{report_key}
        "sort_key": (qp.get("sort_key") or qp.get("sort") or "").strip() or None,
        # keep old "sort" for backward compatibility
        "sort": (qp.get("sort") or "").strip() or None,
        "sort_dir": normalize_sort_dir(qp.get("sort_dir"), default="desc"),
    }

    return f


def paginate(*args, **kwargs) -> Dict[str, Any]:
    """
    Backward-compatible paginator.

    Supported calls:
      1) paginate(request, total=123)  <-- old style used by api.py
      2) paginate(total, page, page_size)
      3) paginate(total=123, page=1, page_size=50)

    Returns:
      dict with keys:
        total, page, page_size, pages, offset, limit, has_prev, has_next, prev_page, next_page
    """
    request = None
    total = None
    page = None
    page_size = None

    # Pattern 1: paginate(request, total=...)
    if args:
        first = args[0]
        # Heuristic: request has query_params
        if hasattr(first, "query_params"):
            request = first
            total = kwargs.get("total", None)
            if total is None and len(args) > 1:
                total = args[1]
        else:
            # Pattern 2: paginate(total, page, page_size)
            total = first
            if len(args) > 1:
                page = args[1]
            if len(args) > 2:
                page_size = args[2]

    # Pull from request if available
    if request is not None:
        qp = request.query_params
        if page is None:
            page = qp.get("page", None)
        if page_size is None:
            page_size = qp.get("page_size", None)

    # Pattern 3: paginate(total=..., page=..., page_size=...)
    if total is None:
        total = kwargs.get("total", 0)
    if page is None:
        page = kwargs.get("page", 1)
    if page_size is None:
        page_size = kwargs.get("page_size", 50)

    total = max(0, int(total or 0))
    page_size = max(1, int(page_size or 50))
    pages = max(1, int(math.ceil(total / page_size))) if total > 0 else 1

    page = max(1, int(page or 1))
    if page > pages:
        page = pages

    offset = (page - 1) * page_size
    limit = page_size

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "offset": offset,
        "limit": limit,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": page - 1 if page > 1 else 1,
        "next_page": page + 1 if page < pages else pages,
    }


def build_pagination(*args, **kwargs) -> Dict[str, Any]:
    """
    Alias for paginate() to prevent ImportError across refactors.
    """
    return paginate(*args, **kwargs)


# ------------------------------------------------------------
# Flash messages (Session-based)
# ------------------------------------------------------------

_FLASH_KEY = "_flash"


def _flash_push(request, level: str, message: str) -> None:
    """
    Store flash messages in request.session if SessionMiddleware exists.
    Each message: {"level": "...", "message": "..."}
    """
    try:
        if request is None:
            return
        sess = getattr(request, "session", None)
        if sess is None:
            return
        arr = sess.get(_FLASH_KEY)
        if not isinstance(arr, list):
            arr = []
        arr.append({"level": str(level), "message": str(message)})
        sess[_FLASH_KEY] = arr
    except Exception:
        return


def flash_error(request, message: str) -> None:
    _flash_push(request, "error", message)


def flash_success(request, message: str) -> None:
    _flash_push(request, "success", message)


def flash_info(request, message: str) -> None:
    _flash_push(request, "info", message)


def flash_warning(request, message: str) -> None:
    _flash_push(request, "warning", message)


def pop_flashes(request) -> List[Dict[str, str]]:
    """
    Pop and clear flash messages.
    """
    try:
        sess = getattr(request, "session", None)
        if sess is None:
            return []
        msgs = sess.get(_FLASH_KEY) or []
        sess[_FLASH_KEY] = []
        return msgs if isinstance(msgs, list) else []
    except Exception:
        return []


# ------------------------------------------------------------
# Querystring builder (used by pagination + links)
# ------------------------------------------------------------

def qs_builder(filters: Optional[Dict[str, Any]] = None):
    f = dict(filters or {})

    def _qs(**overrides):
        merged = dict(f)
        for k, v in overrides.items():
            merged[k] = v

        # remove None / empty values
        cleaned = {}
        for k, v in merged.items():
            if v is None:
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            cleaned[k] = v

        parts = []
        for k, v in cleaned.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    parts.append(f"{k}={item}")
            else:
                parts.append(f"{k}={v}")
        return "&".join(parts)

    return _qs


def build_base_context(request, **kwargs) -> Dict[str, Any]:
    """
    Helper to build template context.
    Adds:
      - request
      - qs / qs_builder for pagination links
      - passes through kwargs
    """
    ctx: Dict[str, Any] = {"request": request}

    try:
        f = kwargs.get("filters") or {}
        ctx["qs"] = qs_builder(f)
        ctx["qs_builder"] = ctx["qs"]
    except Exception:
        pass

    ctx.update(kwargs)
    return ctx
