# core/rules.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Optional
import re
import os


# ---------- Unified rule result model ----------

@dataclass
class RuleResult:
    name: str
    ok: bool
    note: str
    check_command: Optional[str] = None
    warning_regex: Optional[str] = None
    fix_cmd: Optional[str] = None
    rule_type: str = "static"  # static | dynamic
    priority: int = 100
    matched_text: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "note": self.note,
            "check_command": self.check_command,
            "warning_regex": self.warning_regex,
            "fix_cmd": self.fix_cmd,
            "rule_type": self.rule_type,
            "priority": self.priority,
            "matched_text": self.matched_text,
        }


# ---------- Static rules (your current policy) ----------

PUBLIC_DNS_IPS = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}


def build_static_rules(snapshot: Dict[str, Any]) -> Tuple[List[RuleResult], List[str]]:
    rules: List[RuleResult] = []
    warnings: List[str] = []

    pppoe_use_peer_dns = (snapshot.get("pppoe_use_peer_dns") or "").lower()
    pppoe_name = snapshot.get("pppoe_name") or None
    allow_remote_requests = (snapshot.get("allow_remote_requests") or "").lower()
    dhcp_dns = snapshot.get("dhcp_dns_servers") or []
    lan_network = snapshot.get("lan_network")

    # Rule 1
    r1 = RuleResult(
        name="use_peer_dns",
        ok=pppoe_use_peer_dns == "yes",
        note="use-peer-dns يجب أن يكون yes",
        fix_cmd=None,
        rule_type="static",
        priority=10,
    )
    if not r1.ok:
        warnings.append("[!] use-peer-dns ليس 'yes'")
        if pppoe_name:
            r1.fix_cmd = f'/interface pppoe-client set [find where name="{pppoe_name}"] use-peer-dns=yes'
        else:
            r1.fix_cmd = "/interface pppoe-client set [find] use-peer-dns=yes"
    rules.append(r1)

    # Rule 2
    r2 = RuleResult(
        name="allow_remote_requests",
        ok=allow_remote_requests == "yes",
        note="allow-remote-requests يجب أن يكون yes",
        fix_cmd=None,
        rule_type="static",
        priority=20,
    )
    if not r2.ok:
        warnings.append("[!] allow-remote-requests ليس 'yes'")
        r2.fix_cmd = "/ip dns set allow-remote-requests=yes"
    rules.append(r2)

    # Rule 3 (keep light)
    dns_set = set([str(x).strip() for x in dhcp_dns if str(x).strip()])
    public_found = [ip for ip in dns_set if ip in PUBLIC_DNS_IPS]
    r3_ok = (len(dns_set) == 0) or (len(public_found) == 0 and all(ip.startswith(("10.", "172.", "192.168.")) for ip in dns_set))

    r3 = RuleResult(
        name="dhcp_dns_safe",
        ok=r3_ok,
        note="DNS في DHCP network يفضّل يكون فاضي أو محلي فقط",
        fix_cmd=None,
        rule_type="static",
        priority=30,
    )
    if not r3.ok:
        warnings.append(f"[!] DHCP dns-server غير محلي: {sorted(dns_set)}")
        if lan_network:
            r3.fix_cmd = f'/ip dhcp-server network set [find where address="{lan_network}"] dns-server=""'
    rules.append(r3)

    return rules, warnings


# ---------- Dynamic rules (DB regex-based) ----------

@dataclass(frozen=True)
class DynamicRule:
    name: str
    check_command: str
    warning_regex: str
    fix_command: Optional[str]
    priority: int = 100


def _safe_format(template: str, snapshot: Dict[str, Any]) -> str:
    class _SafeDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    return template.format_map(_SafeDict(snapshot))


def load_dynamic_rules_from_db() -> Tuple[List[DynamicRule], Optional[str]]:
    """
    Reads active rules from cpedoctor DB using your existing DBManager.
    Optional ENV overrides:
      CPE_DB_HOST, CPE_DB_PORT, CPE_DB_USER, CPE_DB_PASSWORD, CPE_DB_NAME
    """
    try:
        from core.db_manager import DBManager, DBConfig

        # DBConfig عندك واضح أنه immutable (cannot assign to field)
        # لذا ننشئه مرة واحدة عبر kwargs.
        cfg = DBConfig(
            host=os.getenv("CPE_DB_HOST", getattr(DBConfig, "host", "127.0.0.1")),
            port=int(os.getenv("CPE_DB_PORT", str(getattr(DBConfig, "port", 3306)))),
            user=os.getenv("CPE_DB_USER", getattr(DBConfig, "user", "root")),
            password=os.getenv("CPE_DB_PASSWORD", getattr(DBConfig, "password", "")),
            database=os.getenv("CPE_DB_NAME", getattr(DBConfig, "database", "cpedoctor")),
        )

        db = DBManager(config=cfg)
        rows = db.get_active_rules() or []

        out: List[DynamicRule] = []
        for r in rows:
            out.append(DynamicRule(
                name=str(r.get("name") or "unnamed_rule"),
                check_command=str(r.get("check_command") or "").strip(),
                warning_regex=str(r.get("warning_regex") or "").strip(),
                fix_command=(str(r.get("fix_command")).strip() if r.get("fix_command") is not None else None),
                priority=int(r.get("priority") or 100),
            ))

        out.sort(key=lambda x: x.priority)
        return out, None

    except Exception as exc:
        return [], f"db_rules_load_failed: {exc}"



def evaluate_dynamic_rules(outputs: Dict[str, str], snapshot: Dict[str, Any], rules: List[DynamicRule]) -> Tuple[List[RuleResult], List[str]]:
    results: List[RuleResult] = []
    warnings: List[str] = []

    for r in sorted(rules, key=lambda x: x.priority):
        cmd = r.check_command
        out = outputs.get(cmd, "")
        pattern = r.warning_regex

        ok = True
        matched_text = None

        try:
            m = re.search(pattern, out, flags=re.IGNORECASE | re.MULTILINE)
            if m:
                ok = False
                matched_text = m.group(0)[:200]
        except re.error as rex:
            ok = False
            matched_text = f"bad_regex: {rex}"

        fix_cmd = _safe_format(r.fix_command, snapshot) if (r.fix_command and not ok) else None

        rr = RuleResult(
            name=r.name,
            ok=ok,
            note=f"DynamicRule: cmd='{cmd}' regex='{pattern}'",
            check_command=cmd,
            warning_regex=pattern,
            fix_cmd=fix_cmd,
            rule_type="dynamic",
            priority=r.priority,
            matched_text=matched_text,
        )
        results.append(rr)

        if not ok:
            warnings.append(f"[!] {r.name}")

    return results, warnings


def select_and_evaluate_rules(
    rules_source: str,
    snapshot: Dict[str, Any],
    outputs: Dict[str, str],
) -> Tuple[List[RuleResult], List[str], Dict[str, Any]]:

    meta: Dict[str, Any] = {"rules_source": rules_source}
    src = (rules_source or "static").lower().strip()

    if src == "static":
        rr, warn = build_static_rules(snapshot)
        meta["rules_source_used"] = "static"
        return rr, warn, meta

    if src == "db":
        dyn, err = load_dynamic_rules_from_db()
        meta["dynamic_rules_count"] = len(dyn)
        if err:
            meta["db_error"] = err

        if not dyn:
            rr, warn = build_static_rules(snapshot)
            meta["rules_source_used"] = "static_fallback"
            return rr, warn, meta

        rr, warn = evaluate_dynamic_rules(outputs, snapshot, dyn)
        meta["rules_source_used"] = "db"
        return rr, warn, meta

    if src == "mixed":
        rr_s, warn_s = build_static_rules(snapshot)
        dyn, err = load_dynamic_rules_from_db()
        meta["dynamic_rules_count"] = len(dyn)
        if err:
            meta["db_error"] = err

        rr_d, warn_d = evaluate_dynamic_rules(outputs, snapshot, dyn) if dyn else ([], [])
        all_rr = sorted(rr_s + rr_d, key=lambda x: x.priority)
        meta["rules_source_used"] = "mixed"
        return all_rr, warn_s + warn_d, meta

    rr, warn = build_static_rules(snapshot)
    meta["rules_source_used"] = "static_fallback"
    return rr, warn, meta
