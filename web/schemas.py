from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    ok: bool = True
    app: str


class SessionRow(BaseModel):
    id: int
    status: Optional[str] = None
    mode: Optional[str] = None
    city: Optional[str] = None
    total_cpes: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class InventoryRow(BaseModel):
    pppoe_username: str
    last_ip: Optional[str] = None
    last_city: Optional[str] = None
    last_status: Optional[str] = None
    last_seen_at: Optional[str] = None
    last_fix_applied: Optional[bool] = None
    last_login_success: Optional[bool] = None
