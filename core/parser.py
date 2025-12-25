"""
core/parser.py

دوال بسيطة لتحليل (Parse) مخرجات أوامر MikroTik:

- /interface pppoe-client print detail
- /ip dns print
- /ip dhcp-server network print

ترجع dict منظم يمكن تحويله لاحقاً إلى JSON.
"""

import re
from typing import Dict, Any, List


def _split_ip_list(value: str) -> List[str]:
    """تقسيم قائمة IPs مفصولة بفواصل أو مسافات."""
    if not value:
        return []
    parts = []
    for item in value.replace(",", " ").split():
        item = item.strip()
        if item:
            parts.append(item)
    return parts


# ---------------- PPPoE Detail ----------------

def parse_pppoe_detail(output: str) -> Dict[str, Any]:
    """
    تحليل ناتج:
      /interface pppoe-client print detail

    مثال من بيئتك:

      0  R name="pppoe-111" ... 
           user="WNW100045" ...
           dial-on-demand=no use-peer-dns=yes allow=...

    نبحث عن أول client فيه user و use-peer-dns.
    """

    result: Dict[str, Any] = {
        "name": None,
        "user": None,
        "use_peer_dns": None,
    }

    if not output:
        return result

    # أسهل طريقة: نأخذ أول block يحتوي على user=
    # (في الغالب كله سطر واحد في RouterOS)
    text = output.replace("\r", " ")

    m_name = re.search(r'name="(?P<name>[^"]+)"', text)
    if m_name:
        result["name"] = m_name.group("name")

    m_user = re.search(r'user="(?P<user>[^"]+)"', text)
    if m_user:
        result["user"] = m_user.group("user")

    m_upd = re.search(r"use-peer-dns=(yes|no)", text)
    if m_upd:
        result["use_peer_dns"] = m_upd.group(1)

    return result


# ---------------- IP DNS ----------------

def parse_ip_dns(output: str) -> Dict[str, Any]:
    """
    تحليل ناتج:
      /ip dns print

    مثال (مأخوذ من الأنتينة):

        servers: 
        dynamic-servers: 172.31.1.70,10.100.100.41
        ...
        allow-remote-requests: yes
    """

    result: Dict[str, Any] = {
        "servers": [],
        "dynamic_servers": [],
        "allow_remote_requests": None,
    }

    if not output:
        return result

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("servers:"):
            val = line.split("servers:", 1)[1].strip()
            result["servers"] = _split_ip_list(val)
        elif line.startswith("dynamic-servers:"):
            val = line.split("dynamic-servers:", 1)[1].strip()
            result["dynamic_servers"] = _split_ip_list(val)
        elif line.startswith("allow-remote-requests:"):
            val = line.split("allow-remote-requests:", 1)[1].strip()
            result["allow_remote_requests"] = val

    return result


# ---------------- DHCP Network ----------------

def parse_dhcp_network(output: str) -> Dict[str, Any]:
    """
    تحليل ناتج:
      /ip dhcp-server network print

    ندعم شكلين:
    1) فورم key=value
       address=192.168.50.0/24 gateway=192.168.50.1 dns-server=192.168.50.1

    2) فورم جدول مثل:

       #   ADDRESS            GATEWAY         DNS-SERVER ...
       0   192.168.50.0/24    192.168.50.1    192.168.50.1

    نرجع أول شبكة فقط (يكفي لفحصنا).
    """

    result: Dict[str, Any] = {
        "address": None,
        "gateway": None,
        "dns_server": None,
    }

    if not output:
        return result

    text = output.replace("\r", "")

    # ---- 1) محاولة key=value ----
    m_addr = re.search(r"address=([\d./]+)", text)
    m_gw = re.search(r"gateway=([\d.]+)", text)
    m_dns = re.search(r"dns-server=([0-9.,\s]+)", text, re.IGNORECASE)

    if m_addr or m_gw or m_dns:
        if m_addr:
            result["address"] = m_addr.group(1)
        if m_gw:
            result["gateway"] = m_gw.group(1)
        if m_dns:
            result["dns_server"] = m_dns.group(1).strip()
        return result

    # ---- 2) محاولة شكل الجدول ----
    lines = [ln for ln in text.split("\n") if ln.strip()]
    # نبحث عن أول سطر يبدأ برقم (# index)
    data_line = None
    for ln in lines:
        if re.match(r"^\s*\d+\s", ln):
            data_line = ln
            break

    if data_line:
        # مثال:
        # 0   192.168.50.0/24    192.168.50.1    192.168.50.1
        parts = data_line.split()
        if len(parts) >= 3:
            result["address"] = parts[1]
            result["gateway"] = parts[2]
        if len(parts) >= 4:
            result["dns_server"] = parts[3]

    return result
