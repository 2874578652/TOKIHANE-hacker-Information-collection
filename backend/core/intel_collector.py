import ipaddress
from typing import Callable, Optional

import requests


DEFAULT_REQUEST_HEADERS = {
    "User-Agent": "TOKIHANE-Recon/1.0 (+https://localhost)",
    "Accept": "application/json,text/plain,*/*",
}


def _safe_get_json(url: str, timeout: int, params: dict | None = None) -> dict:
    try:
        response = requests.get(
            url,
            params=params,
            timeout=timeout,
            headers=DEFAULT_REQUEST_HEADERS,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "url": url}

    payload: dict = {"ok": response.ok, "status_code": response.status_code, "url": response.url}
    try:
        payload["data"] = response.json()
    except Exception as exc:  # noqa: BLE001
        payload["error"] = f"Invalid JSON response: {exc}"
        payload["raw_text"] = response.text[:2000]
    return payload


def _normalize_name(name: str) -> str:
    value = (name or "").strip().lower().rstrip(".")
    return value


def collect_certificate_transparency(
    domain: str,
    timeout: int = 15,
    max_entries: int = 300,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    if should_cancel and should_cancel():
        return {"enabled": True, "canceled": True, "message": "Scan canceled before CT collection."}

    url = "https://crt.sh/"
    result = _safe_get_json(
        url=url,
        timeout=timeout,
        params={
            "q": f"%.{domain}",
            "output": "json",
        },
    )
    if not result.get("ok"):
        return {"enabled": True, "error": result.get("error") or f"HTTP {result.get('status_code')}"}

    rows = result.get("data")
    if not isinstance(rows, list):
        return {"enabled": True, "error": "Unexpected crt.sh response format."}

    seen = set()
    subdomains = []
    sample_entries = []
    for row in rows:
        if should_cancel and should_cancel():
            return {"enabled": True, "canceled": True, "message": "CT collection canceled by user."}

        if not isinstance(row, dict):
            continue

        names = []
        common_name = _normalize_name(str(row.get("common_name", "")))
        if common_name:
            names.append(common_name)

        name_value = str(row.get("name_value", ""))
        if name_value:
            for item in name_value.splitlines():
                normalized = _normalize_name(item.replace("*.", ""))
                if normalized:
                    names.append(normalized)

        for name in names:
            if not name or not name.endswith(domain.lower()):
                continue
            if name in seen:
                continue
            seen.add(name)
            subdomains.append(name)

        if len(sample_entries) < max_entries:
            sample_entries.append(
                {
                    "issuer_name": row.get("issuer_name"),
                    "common_name": row.get("common_name"),
                    "entry_timestamp": row.get("entry_timestamp"),
                    "not_before": row.get("not_before"),
                    "not_after": row.get("not_after"),
                    "serial_number": row.get("serial_number"),
                }
            )

    subdomains.sort()
    return {
        "enabled": True,
        "source": "crt.sh",
        "total_records": len(rows),
        "discovered_subdomains": subdomains[:max_entries],
        "sample_entries": sample_entries[:max_entries],
    }


def collect_passive_dns(
    domain: str,
    timeout: int = 15,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    if should_cancel and should_cancel():
        return {"enabled": True, "canceled": True, "message": "Scan canceled before passive DNS collection."}

    result: dict = {
        "enabled": True,
        "sources": {},
        "resolved_ips": [],
        "historical_subdomains": [],
    }

    buffer_payload = _safe_get_json(
        url="https://dns.bufferover.run/dns",
        timeout=timeout,
        params={"q": f".{domain}"},
    )
    result["sources"]["bufferover"] = buffer_payload
    if isinstance(buffer_payload.get("data"), dict):
        data = buffer_payload["data"]
        ips = set()
        domains = set()
        for key in ("FDNS_A", "RDNS"):
            rows = data.get(key)
            if not isinstance(rows, list):
                continue
            for item in rows:
                if not isinstance(item, str) or "," not in item:
                    continue
                left, right = item.split(",", 1)
                left = left.strip()
                right = _normalize_name(right)
                try:
                    ipaddress.ip_address(left)
                    ips.add(left)
                except ValueError:
                    pass
                if right and right.endswith(domain.lower()):
                    domains.add(right)
        result["resolved_ips"] = sorted(ips)
        result["historical_subdomains"] = sorted(domains)

    if should_cancel and should_cancel():
        result["canceled"] = True
        result["message"] = "Passive DNS collection canceled by user."
        return result

    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    otx_payload = _safe_get_json(url=otx_url, timeout=timeout)
    result["sources"]["otx_passive_dns"] = otx_payload
    if isinstance(otx_payload.get("data"), dict):
        entries = otx_payload["data"].get("passive_dns", [])
        if isinstance(entries, list):
            ips = set(result["resolved_ips"])
            domains = set(result["historical_subdomains"])
            sample = []
            for row in entries[:400]:
                if not isinstance(row, dict):
                    continue
                hostname = _normalize_name(str(row.get("hostname", "")))
                addr = str(row.get("address", "")).strip()
                if hostname and hostname.endswith(domain.lower()):
                    domains.add(hostname)
                try:
                    ipaddress.ip_address(addr)
                    ips.add(addr)
                except ValueError:
                    pass
                if len(sample) < 200:
                    sample.append(
                        {
                            "hostname": row.get("hostname"),
                            "address": row.get("address"),
                            "first": row.get("first"),
                            "last": row.get("last"),
                            "record_type": row.get("record_type"),
                        }
                    )
            result["resolved_ips"] = sorted(ips)
            result["historical_subdomains"] = sorted(domains)
            result["otx_sample"] = sample

    return result


def _query_bgpview_for_ip(ip: str, timeout: int) -> dict:
    endpoint = f"https://api.bgpview.io/ip/{ip}"
    payload = _safe_get_json(endpoint, timeout=timeout)
    if not payload.get("ok"):
        return {"ip": ip, "error": payload.get("error") or f"HTTP {payload.get('status_code')}"}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {"ip": ip, "error": "Unexpected bgpview format."}

    prefix = None
    prefixes = data.get("prefixes")
    if isinstance(prefixes, list) and prefixes:
        first = prefixes[0]
        if isinstance(first, dict):
            prefix = first.get("prefix")

    asn_info = data.get("asn")
    asn_number = None
    asn_name = None
    if isinstance(asn_info, dict):
        asn_number = asn_info.get("asn")
        asn_name = asn_info.get("description_short") or asn_info.get("name")

    return {
        "ip": ip,
        "asn": asn_number,
        "asn_name": asn_name,
        "prefix": prefix,
        "country_code": data.get("country_code"),
        "rir_name": data.get("rir_name"),
    }


def _expand_c_segment(ip: str, limit: int = 64) -> list[str]:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if parsed.version != 4:
        return []

    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    hosts = []
    for candidate in network.hosts():
        value = str(candidate)
        if value == ip:
            continue
        hosts.append(value)
        if len(hosts) >= max(1, limit):
            break
    return hosts


def collect_asn_and_network_expansion(
    ips: list[str],
    timeout: int = 15,
    expand_c_segment: bool = False,
    c_segment_limit: int = 64,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    if should_cancel and should_cancel():
        return {"enabled": True, "canceled": True, "message": "Scan canceled before ASN collection."}

    reports = []
    expanded_hosts = set()
    for ip in ips:
        if should_cancel and should_cancel():
            return {
                "enabled": True,
                "canceled": True,
                "records": reports,
                "expanded_c_segment_hosts": sorted(expanded_hosts),
                "message": "ASN collection canceled by user.",
            }

        row = _query_bgpview_for_ip(ip=ip, timeout=timeout)
        row["c_segment"] = f"{ip.rsplit('.', 1)[0]}.0/24" if "." in ip else None
        if expand_c_segment:
            row["c_segment_expansion"] = _expand_c_segment(ip=ip, limit=c_segment_limit)
            expanded_hosts.update(row["c_segment_expansion"])
        reports.append(row)

    return {
        "enabled": True,
        "expand_c_segment": expand_c_segment,
        "c_segment_limit": c_segment_limit,
        "records": reports,
        "expanded_c_segment_hosts": sorted(expanded_hosts),
    }
