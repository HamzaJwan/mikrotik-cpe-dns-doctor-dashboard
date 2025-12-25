#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MikroTik CPE DNS Doctor - Single CPE Engine
-------------------------------------------
CLI + Library (for multi_cpe.py)

تحديث مهم:
- imports الآن صحيحة حسب هيكل مشروعك (core/*).
- منطق الـ Rules صار يستدعي core.rules (مكان واحد).
- إضافة --rules-source: static | db | mixed

تحديث (هذه النسخة):
- إصلاح عرض MODE: يظهر fix+reboot كما أدخلته.
- reboot مشروط: لا يُنفذ إلا عند وجود Fix فعلي + تغيّر DHCP DNS أو use-peer-dns.
- تسجيل ماذا تغير ولماذا داخل summary (changes + fixes_applied + reboot_*).
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from core.mikrotik_telnet import MikroTikTelnetClient
from core.parser import parse_pppoe_detail, parse_ip_dns, parse_dhcp_network
from core.rules import select_and_evaluate_rules


# ------------------ Helpers ------------------

def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def save_raw_log(ip: str, raw_text: str, logs_dir: str = "logs") -> str:
    ensure_dir(logs_dir)
    fn = os.path.join(logs_dir, f"raw_{ip}_{now_stamp()}.txt")
    with open(fn, "w", encoding="utf-8", errors="ignore") as f:
        f.write(raw_text)
    return fn


def save_summary_json(ip: str, payload: Dict[str, Any], logs_dir: str = "logs") -> str:
    ensure_dir(logs_dir)
    fn = os.path.join(logs_dir, f"summary_{ip}_{now_stamp()}.json")
    with open(fn, "w", encoding="utf-8", errors="ignore") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return fn


def load_password_candidates(password: Optional[str], password_file: Optional[str]) -> List[str]:
    candidates: List[str] = []

    if password is not None:
        candidates.append(password)

    if password_file:
        try:
            with open(password_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pw = line.strip("\r\n")
                    if pw == "":
                        candidates.append("")
                    else:
                        candidates.append(pw)
        except FileNotFoundError:
            pass

    seen = set()
    ordered: List[str] = []
    for pw in candidates:
        key = "__EMPTY__" if pw == "" else pw
        if key in seen:
            continue
        seen.add(key)
        ordered.append(pw)

    return ordered


class LoginFailed(Exception):
    pass


def connect_with_passwords(ip: str, timeout: int, passwords: List[str], user: str = "admin") -> Tuple[MikroTikTelnetClient, str]:
    last_exc: Optional[Exception] = None

    for pw in passwords:
        client = MikroTikTelnetClient(ip=ip, username=user, password=pw, timeout=timeout)

        try:
            client.connect()
            client.run_command("/system identity print")
            return client, pw
        except Exception as exc:
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass

    raise LoginFailed(str(last_exc) if last_exc else "login_failed")


def collect_outputs(client: MikroTikTelnetClient) -> Tuple[Dict[str, str], str]:
    commands = [
        "/interface pppoe-client print detail",
        "/ip dns print",
        "/ip dhcp-server network print",
    ]

    outputs: Dict[str, str] = {}
    raw_chunks: List[str] = []

    for cmd in commands:
        out = client.run_command(cmd)
        outputs[cmd] = out
        raw_chunks.append(f"{cmd}\n{out}\n")

    raw_text = "\n".join(raw_chunks)
    return outputs, raw_text


def build_snapshot_from_outputs(cpe_ip: str, mode: str, outputs: Dict[str, str]) -> Dict[str, Any]:
    pppoe_info = parse_pppoe_detail(outputs["/interface pppoe-client print detail"])
    dns_info = parse_ip_dns(outputs["/ip dns print"])
    dhcp_info = parse_dhcp_network(outputs["/ip dhcp-server network print"])

    snapshot: Dict[str, Any] = {
        "cpe_ip": cpe_ip,
        "mode": mode,

        "pppoe_name": pppoe_info.get("name"),
        "pppoe_username": pppoe_info.get("user") or "UNKNOWN",
        "pppoe_use_peer_dns": pppoe_info.get("use_peer_dns") or "unknown",

        "router_dns_servers": dns_info.get("dynamic_servers", []),
        "allow_remote_requests": dns_info.get("allow_remote_requests"),

        "lan_network": dhcp_info.get("address"),
        "lan_gateway": dhcp_info.get("gateway"),
        "dhcp_dns_servers": [dhcp_info["dns_server"]] if dhcp_info.get("dns_server") else [],
    }

    return snapshot


def compute_status(mode_raw: str, fix_applied: bool, warnings_count: int) -> str:
    if warnings_count == 0:
        return "ok"
    if mode_raw.startswith("fix") and fix_applied:
        return "fixed"
    return "warn"


def _normalize_list(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip() != ""]
    return [str(v).strip()] if str(v).strip() != "" else []


# ------------------ Engine ------------------

def process_cpe(
    ip: str,
    mode_raw: str = "audit",          # audit | fix | fix+reboot
    timeout: int = 10,
    user: str = "admin",
    password: Optional[str] = None,
    password_file: Optional[str] = None,
    city: Optional[str] = None,
    save_logs: bool = False,
    rules_source: str = "static",     # static | db | mixed
) -> Dict[str, Any]:

    internal_mode = "fix" if mode_raw.startswith("fix") else "audit"
    wants_reboot = (mode_raw == "fix+reboot")

    passwords = load_password_candidates(password=password, password_file=password_file)

    summary: Dict[str, Any] = {
        "cpe_ip": ip,
        "city": city,

        # show the real CLI mode entered by the operator
        "mode": mode_raw,
        "internal_mode": internal_mode,

        "rules_source": rules_source,

        "status": "failed",
        "warning_count": 0,

        "login_success": False,
        "password_used": None,
        "password_used_is_empty": None,

        "pppoe_username": "UNKNOWN",

        "fix_applied": False,
        "fix_verified": None,
        "fixes_applied": [],

        "reboot_requested": False,
        "reboot_executed": False,
        "reboot_reason": None,

        "changes": {},

        "rules_meta": {},
    }

    warnings: List[str] = []
    rules_result: List[Dict[str, Any]] = []
    raw_text: str = ""

    client: Optional[MikroTikTelnetClient] = None

    try:
        client, pw_used = connect_with_passwords(ip=ip, timeout=timeout, passwords=passwords, user=user)
        summary["login_success"] = True
        summary["password_used"] = pw_used
        summary["password_used_is_empty"] = (pw_used == "")

        # ---- BEFORE snapshot ----
        outputs, raw_text = collect_outputs(client)
        snapshot_before = build_snapshot_from_outputs(ip, internal_mode, outputs)

        summary["pppoe_username"] = snapshot_before.get("pppoe_username") or "UNKNOWN"
        summary["pppoe_use_peer_dns_before"] = snapshot_before.get("pppoe_use_peer_dns")
        summary["allow_remote_requests_before"] = snapshot_before.get("allow_remote_requests")
        summary["dhcp_dns_servers_before"] = _normalize_list(snapshot_before.get("dhcp_dns_servers"))

        rr_objects, warn_list, meta = select_and_evaluate_rules(rules_source, snapshot_before, outputs)
        warnings = warn_list
        rules_result = [r.to_dict() for r in rr_objects]
        summary["rules_meta"] = meta
        summary["warning_count"] = len(warnings)

        fix_applied = False
        fixes_applied: List[Dict[str, Any]] = []

        # ---- APPLY FIXES ----
        if internal_mode == "fix":
            for r in rr_objects:
                if r.ok:
                    continue
                if not r.fix_cmd:
                    continue

                item = {
                    "rule_name": getattr(r, "name", None),
                    "fix_cmd": getattr(r, "fix_cmd", None),
                    "applied": False,
                    "error": None,
                }

                try:
                    client.run_command(r.fix_cmd)
                    item["applied"] = True
                    fix_applied = True
                except Exception as ex:
                    item["error"] = str(ex)

                fixes_applied.append(item)

            summary["fix_applied"] = fix_applied
            summary["fixes_applied"] = fixes_applied

            # ---- AFTER snapshot + verification ----
            outputs2, raw_text2 = collect_outputs(client)
            raw_text = raw_text2
            snapshot_after = build_snapshot_from_outputs(ip, internal_mode, outputs2)

            rr2, warn2, meta2 = select_and_evaluate_rules(rules_source, snapshot_after, outputs2)
            warnings = warn2
            rules_result = [r.to_dict() for r in rr2]
            summary["rules_meta"] = meta2
            summary["warning_count"] = len(warnings)

            summary["pppoe_use_peer_dns_after"] = snapshot_after.get("pppoe_use_peer_dns")
            summary["allow_remote_requests_after"] = snapshot_after.get("allow_remote_requests")
            summary["dhcp_dns_servers_after"] = _normalize_list(snapshot_after.get("dhcp_dns_servers"))

            summary["fix_verified"] = (len(warnings) == 0)

            # ---- CHANGE DETECTION (for conditional reboot + reports) ----
            before_dhcp = _normalize_list(summary.get("dhcp_dns_servers_before"))
            after_dhcp = _normalize_list(summary.get("dhcp_dns_servers_after"))
            dhcp_dns_changed = (before_dhcp != after_dhcp)

            before_peer = summary.get("pppoe_use_peer_dns_before")
            after_peer = summary.get("pppoe_use_peer_dns_after")
            use_peer_dns_changed = (before_peer != after_peer)

            summary["changes"] = {
                "dhcp_dns_changed": dhcp_dns_changed,
                "use_peer_dns_changed": use_peer_dns_changed,
                "before": {
                    "dhcp_dns_servers": before_dhcp,
                    "pppoe_use_peer_dns": before_peer,
                    "allow_remote_requests": summary.get("allow_remote_requests_before"),
                },
                "after": {
                    "dhcp_dns_servers": after_dhcp,
                    "pppoe_use_peer_dns": after_peer,
                    "allow_remote_requests": summary.get("allow_remote_requests_after"),
                },
            }

            # ---- Conditional reboot policy (your requested policy) ----
            reboot_needed = False
            reboot_reason = None

            if wants_reboot and fix_applied:
                # reboot is only required when DHCP DNS changes or peer-dns changes
                if dhcp_dns_changed:
                    reboot_needed = True
                    reboot_reason = "dhcp_network_dns_changed"
                elif use_peer_dns_changed:
                    reboot_needed = True
                    reboot_reason = "pppoe_use_peer_dns_changed"

            summary["reboot_requested"] = reboot_needed
            summary["reboot_reason"] = reboot_reason

            if reboot_needed:
                try:
                    client.reboot(confirm=True)
                    summary["reboot_executed"] = True
                except Exception as ex:
                    summary["reboot_executed"] = False
                    summary["reboot_error"] = str(ex)

        summary["status"] = compute_status(mode_raw, summary.get("fix_applied", False), summary.get("warning_count", 0))

    except Exception as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc)

    finally:
        try:
            if client:
                client.close()
        except Exception:
            pass

    if save_logs:
        save_raw_log(ip, raw_text)
        save_summary_json(ip, {
            "summary": summary,
            "warnings": warnings,
            "rules_result": rules_result,
            "raw_output_text": raw_text,
        })

    return {
        "summary": summary,
        "warnings": warnings,
        "rules_result": rules_result,
        "raw_output_text": raw_text,
    }


# ------------------ CLI ------------------

def print_cli_summary(res: Dict[str, Any]) -> None:
    summary = res.get("summary", {}) or {}
    warnings = res.get("warnings", []) or []

    print("========================================")
    print("          Single CPE DNS Doctor")
    print("========================================")
    print(f"IP: {summary.get('cpe_ip')}")
    print(f"MODE: {summary.get('mode')}")
    print(f"RULES_SOURCE: {summary.get('rules_source')}")
    print(f"STATUS: {summary.get('status')}")
    print(f"LOGIN_SUCCESS: {summary.get('login_success')}")
    print(f"PASSWORD_USED_EMPTY: {summary.get('password_used_is_empty')}")
    print(f"PPPoE USER: {summary.get('pppoe_username')}")
    print(f"WARNINGS: {summary.get('warning_count')}")

    if summary.get("mode") == "fix+reboot":
        print(f"REBOOT_REQUESTED: {summary.get('reboot_requested')}")
        print(f"REBOOT_EXECUTED: {summary.get('reboot_executed')}")
        print(f"REBOOT_REASON: {summary.get('reboot_reason')}")

    if warnings:
        for w in warnings:
            print(w)


def main() -> int:
    ap = argparse.ArgumentParser(description="MikroTik CPE DNS Doctor (single)")
    ap.add_argument("--ip", required=True, help="CPE IP")
    ap.add_argument("--mode", default="audit", choices=["audit", "fix", "fix+reboot"])
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default=None)
    ap.add_argument("--password-file", default=None)
    ap.add_argument("--city", default=None)
    ap.add_argument("--save-logs", action="store_true")
    ap.add_argument("--rules-source", default="static", choices=["static", "db", "mixed"])

    args = ap.parse_args()

    res = process_cpe(
        ip=args.ip,
        mode_raw=args.mode,                 # <-- keep real mode
        timeout=args.timeout,
        user=args.user,
        password=args.password,
        password_file=args.password_file,
        city=args.city,
        save_logs=args.save_logs,
        rules_source=args.rules_source,
    )

    print_cli_summary(res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
