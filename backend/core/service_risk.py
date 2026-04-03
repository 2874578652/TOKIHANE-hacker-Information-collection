import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Callable, Optional

import requests


TLS_COMMON_PORTS = {443, 465, 587, 993, 995, 8443}


def _collect_service_inventory(ip_scan: dict) -> list[dict]:
    inventory = []
    for ip, record in (ip_scan.get("results") or {}).items():
        for protocol in ("tcp", "udp"):
            result = (record or {}).get(protocol, {})
            for row in result.get("open_ports", []) or []:
                if not isinstance(row, dict):
                    continue
                inventory.append(
                    {
                        "ip": ip,
                        "port": row.get("port"),
                        "protocol": row.get("protocol", protocol),
                        "service": row.get("service"),
                        "banner": row.get("banner"),
                        "state": row.get("state"),
                        "cpe": row.get("cpe") if isinstance(row.get("cpe"), list) else [],
                    }
                )
    return inventory


def _query_nvd_by_cpe(cpe: str, timeout: int = 12, api_key: Optional[str] = None) -> dict:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "TOKIHANE-Recon/1.0 (+https://localhost)"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(
            endpoint,
            params={"cpeName": cpe, "resultsPerPage": 10},
            timeout=timeout,
            headers=headers,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "cpe": cpe}

    if not response.ok:
        return {
            "ok": False,
            "error": f"NVD HTTP {response.status_code}",
            "status_code": response.status_code,
            "cpe": cpe,
        }

    try:
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"NVD invalid JSON: {exc}", "cpe": cpe}

    vulnerabilities = []
    for row in payload.get("vulnerabilities", [])[:10]:
        if not isinstance(row, dict):
            continue
        cve = row.get("cve", {})
        if not isinstance(cve, dict):
            continue

        metrics = cve.get("metrics", {})
        score = None
        severity = None
        if isinstance(metrics, dict):
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key)
                if isinstance(entries, list) and entries:
                    metric_data = entries[0].get("cvssData", {})
                    score = metric_data.get("baseScore")
                    severity = metric_data.get("baseSeverity")
                    break

        vulnerabilities.append(
            {
                "id": cve.get("id"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "base_score": score,
                "severity": severity,
                "description": (
                    (cve.get("descriptions") or [{}])[0].get("value")
                    if isinstance(cve.get("descriptions"), list)
                    else None
                ),
            }
        )

    return {
        "ok": True,
        "cpe": cpe,
        "total_results": payload.get("totalResults"),
        "cves": vulnerabilities,
    }


def _run_nmap_script(
    ip: str,
    ports: list[int],
    script: str,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_process_start: Optional[Callable[[subprocess.Popen], None]] = None,
    on_process_end: Optional[Callable[[], None]] = None,
) -> dict:
    if should_cancel and should_cancel():
        return {"enabled": True, "canceled": True, "message": "Risk check canceled by user."}

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return {"enabled": False, "error": "nmap not found in PATH."}
    if not ports:
        return {"enabled": True, "message": "No matching open ports for this check."}

    port_arg = ",".join(str(port) for port in sorted(set(ports)))
    command = [
        nmap_path,
        "-n",
        "-Pn",
        "-p",
        port_arg,
        "--script",
        script,
        "-oX",
        "-",
        ip,
    ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if on_process_start:
            on_process_start(process)

        while process.poll() is None:
            if should_cancel and should_cancel():
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                return {"enabled": True, "canceled": True, "message": "Risk check canceled by user."}
            time.sleep(0.1)

        stdout, stderr = process.communicate()
        if process.returncode != 0 and not stdout.strip():
            return {"enabled": False, "error": stderr.strip() or "nmap script failed."}

        parsed = _parse_nmap_script_xml(stdout, script_name=script)
        parsed["raw_stderr"] = stderr.strip()
        return parsed
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": f"Failed to execute nmap script: {exc}"}
    finally:
        if on_process_end:
            on_process_end()


def _parse_nmap_script_xml(xml_text: str, script_name: str) -> dict:
    findings = []
    try:
        root = ET.fromstring(xml_text)
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": f"Invalid nmap XML output: {exc}"}

    for port in root.findall(".//host/ports/port"):
        protocol = port.attrib.get("protocol")
        port_id = port.attrib.get("portid")
        for script in port.findall("script"):
            if script.attrib.get("id") != script_name:
                continue
            output = script.attrib.get("output", "")
            findings.append(
                {
                    "protocol": protocol,
                    "port": int(port_id) if port_id and port_id.isdigit() else port_id,
                    "script": script_name,
                    "output": output,
                }
            )

    return {
        "enabled": True,
        "script": script_name,
        "finding_count": len(findings),
        "findings": findings,
    }


def collect_service_risk(
    ip_scan: dict,
    cve_lookup: bool = True,
    weak_nmap_checks: bool = True,
    timeout: int = 12,
    nvd_api_key: Optional[str] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_process_start: Optional[Callable[[subprocess.Popen], None]] = None,
    on_process_end: Optional[Callable[[], None]] = None,
) -> dict:
    inventory = _collect_service_inventory(ip_scan)
    result: dict = {
        "enabled": True,
        "service_count": len(inventory),
        "services": inventory,
        "cve_lookup": {"enabled": cve_lookup},
        "weak_checks": {"enabled": weak_nmap_checks},
    }

    if should_cancel and should_cancel():
        result["canceled"] = True
        result["message"] = "Service risk analysis canceled by user."
        return result

    if cve_lookup:
        cpe_set = set()
        for svc in inventory:
            for cpe in svc.get("cpe", []):
                if isinstance(cpe, str) and cpe.strip():
                    cpe_set.add(cpe.strip())

        cve_rows = []
        for cpe in sorted(cpe_set):
            if should_cancel and should_cancel():
                result["canceled"] = True
                result["message"] = "Service risk analysis canceled by user."
                result["cve_lookup"]["matches"] = cve_rows
                return result
            cve_rows.append(_query_nvd_by_cpe(cpe=cpe, timeout=timeout, api_key=nvd_api_key))
        result["cve_lookup"]["cpe_count"] = len(cpe_set)
        result["cve_lookup"]["matches"] = cve_rows
    else:
        result["cve_lookup"]["message"] = "CVE lookup disabled by user."

    if weak_nmap_checks:
        weak_by_ip = {}
        for ip, row in (ip_scan.get("results") or {}).items():
            tcp_ports = []
            for port_row in (row.get("tcp", {}).get("open_ports") or []):
                if isinstance(port_row, dict) and isinstance(port_row.get("port"), int):
                    tcp_ports.append(port_row["port"])

            ftp_ports = [p for p in tcp_ports if p == 21]
            tls_ports = sorted(set([p for p in tcp_ports if p in TLS_COMMON_PORTS]))
            for port_row in (row.get("tcp", {}).get("open_ports") or []):
                if not isinstance(port_row, dict):
                    continue
                service_name = str(port_row.get("service", "")).lower()
                port_num = port_row.get("port")
                if isinstance(port_num, int) and any(key in service_name for key in ("https", "ssl", "tls")):
                    tls_ports.append(port_num)

            weak_by_ip[ip] = {
                "ftp_anonymous_check": _run_nmap_script(
                    ip=ip,
                    ports=ftp_ports,
                    script="ftp-anon",
                    should_cancel=should_cancel,
                    on_process_start=on_process_start,
                    on_process_end=on_process_end,
                ),
                "tls_cipher_check": _run_nmap_script(
                    ip=ip,
                    ports=sorted(set(tls_ports)),
                    script="ssl-enum-ciphers",
                    should_cancel=should_cancel,
                    on_process_start=on_process_start,
                    on_process_end=on_process_end,
                ),
            }
        result["weak_checks"]["per_ip"] = weak_by_ip
    else:
        result["weak_checks"]["message"] = "Weak configuration checks disabled by user."

    return result
