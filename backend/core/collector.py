import subprocess
import ipaddress
from typing import Callable, Optional

from core.dns_collector import collect_dns
from core.ip_collector import collect_ip_info
from core.intel_collector import (
    collect_asn_and_network_expansion,
    collect_certificate_transparency,
    collect_passive_dns,
)
from core.service_risk import collect_service_risk
from core.target_parser import parse_target
from core.tech_detector import detect_tech_stack
from core.virustotal import query_virustotal
from core.web_enum import collect_web_assets
from core.whois_collector import collect_whois


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _collect_candidate_ips(target_domain: str, dns_result: dict, passive_dns_result: dict | None = None) -> list[str]:
    candidates = []
    if _is_ip(target_domain):
        candidates.append(target_domain)

    for record_type in ["A", "AAAA"]:
        answers = dns_result.get(record_type)
        if isinstance(answers, list):
            for answer in answers:
                if _is_ip(answer):
                    candidates.append(answer)

    if passive_dns_result and isinstance(passive_dns_result.get("resolved_ips"), list):
        for answer in passive_dns_result["resolved_ips"]:
            if _is_ip(answer):
                candidates.append(answer)

    deduped = []
    seen = set()
    for ip in candidates:
        if ip in seen:
            continue
        seen.add(ip)
        deduped.append(ip)
    return deduped


def collect_information(
    target: str,
    timeout: int = 10,
    vt_api_key: Optional[str] = None,
    vt_scan: bool = True,
    port_range: str = "1-1024",
    port_timeout: float = 0.8,
    port_workers: int = 200,
    port_scanner: str = "auto",
    full_port_scan: bool = False,
    tcp_scan: bool = True,
    udp_scan: bool = False,
    allow_private_ip: bool = False,
    cidr_targets: str = "",
    cidr_host_limit: int = 256,
    ct_scan: bool = False,
    passive_dns_scan: bool = False,
    asn_scan: bool = False,
    asn_expand_c_segment: bool = False,
    web_asset_scan: bool = False,
    web_crawler: bool = True,
    web_js_extract: bool = True,
    web_sensitive_path_extract: bool = True,
    web_dir_scan: bool = True,
    web_dir_use_ffuf: bool = False,
    service_risk_scan: bool = False,
    cve_lookup: bool = False,
    weak_nmap_checks: bool = False,
    nvd_api_key: Optional[str] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_process_start: Optional[Callable[[subprocess.Popen], None]] = None,
    on_process_end: Optional[Callable[[], None]] = None,
) -> dict:
    def is_canceled() -> bool:
        return bool(should_cancel and should_cancel())

    report: dict = {}

    try:
        parsed = parse_target(target)
    except ValueError as exc:
        return {"error": str(exc)}

    report["target"] = parsed

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before DNS collection.",
        }

    domain = parsed["domain"]
    normalized_url = parsed["normalized_url"]
    dns_result = collect_dns(domain=domain, timeout=timeout)
    report["dns"] = dns_result

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before CT/passive DNS collection.",
        }

    if ct_scan:
        report["certificate_transparency"] = collect_certificate_transparency(
            domain=domain,
            timeout=timeout,
            should_cancel=should_cancel,
        )
    else:
        report["certificate_transparency"] = {
            "enabled": False,
            "message": "Certificate transparency collection disabled by user.",
        }

    if passive_dns_scan:
        report["passive_dns"] = collect_passive_dns(
            domain=domain,
            timeout=timeout,
            should_cancel=should_cancel,
        )
    else:
        report["passive_dns"] = {
            "enabled": False,
            "message": "Passive/historical DNS collection disabled by user.",
        }

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before WHOIS collection.",
        }

    report["whois"] = collect_whois(domain=domain)

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before tech stack detection.",
        }

    report["tech_stack"] = detect_tech_stack(url=normalized_url, timeout=timeout)

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before VirusTotal query.",
        }

    if vt_scan:
        report["virustotal"] = query_virustotal(
            domain=domain,
            normalized_url=normalized_url,
            api_key=vt_api_key or "",
            timeout=timeout,
        )
    else:
        report["virustotal"] = {
            "enabled": False,
            "message": "VirusTotal scan disabled by user.",
        }

    if asn_scan:
        candidate_ips = _collect_candidate_ips(
            target_domain=domain,
            dns_result=dns_result,
            passive_dns_result=report.get("passive_dns") if passive_dns_scan else None,
        )
        report["asn_network"] = collect_asn_and_network_expansion(
            ips=candidate_ips,
            timeout=timeout,
            expand_c_segment=asn_expand_c_segment,
            should_cancel=should_cancel,
        )
    else:
        report["asn_network"] = {
            "enabled": False,
            "message": "ASN/C-segment expansion disabled by user.",
        }

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before web asset enumeration.",
        }

    if web_asset_scan:
        report["web_assets"] = collect_web_assets(
            normalized_url=normalized_url,
            timeout=timeout,
            web_crawler=web_crawler,
            web_js_extract=web_js_extract,
            web_sensitive_path_extract=web_sensitive_path_extract,
            web_dir_scan=web_dir_scan,
            web_dir_use_ffuf=web_dir_use_ffuf,
            should_cancel=should_cancel,
        )
    else:
        report["web_assets"] = {
            "enabled": False,
            "message": "Web asset enumeration disabled by user.",
        }

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before IP scan.",
        }

    report["ip_scan"] = collect_ip_info(
        target_domain=domain,
        dns_result=dns_result,
        port_range=port_range,
        timeout=port_timeout,
        workers=port_workers,
        scanner=port_scanner,
        full_port_scan=full_port_scan,
        tcp_scan=tcp_scan,
        udp_scan=udp_scan,
        allow_private_ip=allow_private_ip,
        cidr_targets=cidr_targets,
        cidr_host_limit=cidr_host_limit,
        should_cancel=should_cancel,
        on_process_start=on_process_start,
        on_process_end=on_process_end,
    )

    if is_canceled():
        return {
            **report,
            "canceled": True,
            "message": "Scan canceled before service risk analysis.",
        }

    if service_risk_scan:
        report["service_risk"] = collect_service_risk(
            ip_scan=report["ip_scan"],
            cve_lookup=cve_lookup,
            weak_nmap_checks=weak_nmap_checks,
            timeout=timeout,
            nvd_api_key=nvd_api_key,
            should_cancel=should_cancel,
            on_process_start=on_process_start,
            on_process_end=on_process_end,
        )
    else:
        report["service_risk"] = {
            "enabled": False,
            "message": "Service risk correlation disabled by user.",
        }
    return report
