import ipaddress
import os
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


def _parse_ports(port_range: str) -> list[int]:
    ports = set()
    for chunk in (item.strip() for item in port_range.split(",")):
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", maxsplit=1)
            start = int(start_text.strip())
            end = int(end_text.strip())
            if start > end:
                raise ValueError(f"Invalid range: {chunk}")
            for port in range(start, end + 1):
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            continue

        port = int(chunk)
        if port < 1 or port > 65535:
            raise ValueError(f"Port out of range: {port}")
        ports.add(port)

    if not ports:
        raise ValueError("No valid ports provided.")
    return sorted(ports)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_real_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _extract_ips(target_domain: str, dns_result: dict) -> list[str]:
    candidates = []
    if _is_ip(target_domain):
        candidates.append(target_domain)

    for record_type in ["A", "AAAA"]:
        answers = dns_result.get(record_type)
        if isinstance(answers, list):
            for answer in answers:
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


def _expand_cidr_targets(cidr_targets: str, host_limit_per_cidr: int = 256, total_limit: int = 2048) -> tuple[list[str], list[str], bool]:
    if not cidr_targets:
        return [], [], False

    expanded_hosts = []
    invalid_cidrs = []
    truncated = False
    seen = set()

    for chunk in (item.strip() for item in cidr_targets.split(",")):
        if not chunk:
            continue
        try:
            network = ipaddress.ip_network(chunk, strict=False)
        except ValueError:
            invalid_cidrs.append(chunk)
            continue

        host_count = 0
        for host in network.hosts():
            host_ip = str(host)
            if host_ip in seen:
                continue
            seen.add(host_ip)
            expanded_hosts.append(host_ip)
            host_count += 1

            if host_count >= max(1, host_limit_per_cidr):
                truncated = True
                break
            if len(expanded_hosts) >= max(1, total_limit):
                truncated = True
                return expanded_hosts, invalid_cidrs, truncated

    return expanded_hosts, invalid_cidrs, truncated


def _port_list_to_nmap_range(ports: list[int]) -> str:
    if not ports:
        return ""

    ranges = []
    start = ports[0]
    prev = ports[0]

    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue

        if start == prev:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{prev}")

        start = port
        prev = port

    if start == prev:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{prev}")

    return ",".join(ranges)


def _estimate_host_timeout_seconds(port_count: int, timeout_base: float, udp_scan: bool) -> int:
    # Keep WAN scans stable: full-port + UDP can take long, but avoid infinite waits.
    if port_count <= 0:
        return 120
    multiplier = 2.8 if udp_scan else 1.6
    estimated = int(max(30, port_count * max(0.05, timeout_base) * multiplier))
    return min(3600, estimated)


def _build_nmap_env() -> dict:
    # Avoid accidental proxy chaining through env vars when users run in proxied shells.
    env = os.environ.copy()
    for key in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ):
        env.pop(key, None)
    return env


def _choose_tcp_scan_args() -> tuple[list[str], str]:
    # Prefer SYN scan when privileged (more accurate under proxy/tunnel environments).
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        try:
            if geteuid() == 0:
                return ["-sS", "-sV", "--version-light"], "syn"
        except Exception:  # noqa: BLE001
            pass
    return ["-sT", "-sV", "--version-light"], "connect"


def _attach_suspicious_open_warning(result: dict, protocol: str) -> dict:
    if not isinstance(result, dict):
        return result
    scanned = int(result.get("scanned_port_count") or 0)
    open_count = int(result.get("open_port_count") or 0)
    if scanned >= 100 and open_count >= int(scanned * 0.85):
        result["warning"] = (
            f"Suspicious {protocol} result: {open_count}/{scanned} ports reported open. "
            "This can be caused by VPN/TUN/proxy interception. "
            "Try DIRECT routing or scan without proxy."
        )
    return result


def _guess_builtin_service(port: int, protocol: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def _scan_with_builtin_socket(
    ip: str,
    ports: list[int],
    timeout: float,
    workers: int,
    tcp_scan: bool,
    udp_scan: bool,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> tuple[dict, dict]:
    def canceled_response() -> tuple[dict, dict]:
        message = "Scan canceled by user."
        return (
            {"enabled": False, "canceled": True, "message": message, "scanner": "builtin"},
            {"enabled": False, "canceled": True, "message": message, "scanner": "builtin"},
        )

    if should_cancel and should_cancel():
        return canceled_response()

    if not tcp_scan and not udp_scan:
        message = "Both TCP and UDP scan are disabled."
        return (
            {"enabled": False, "message": message, "scanner": "builtin"},
            {"enabled": False, "message": message, "scanner": "builtin"},
        )

    tcp_result: dict = {"enabled": False, "message": "TCP scan disabled.", "scanner": "builtin"}
    udp_result: dict = {"enabled": False, "message": "UDP scan disabled.", "scanner": "builtin"}

    if tcp_scan:
        open_ports = []

        def scan_tcp_port(port: int) -> dict | None:
            if should_cancel and should_cancel():
                return None
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    return {
                        "port": int(port),
                        "protocol": "tcp",
                        "service": _guess_builtin_service(port, "tcp"),
                        "state": "open",
                        "banner": None,
                        "cpe": [],
                    }
            except OSError:
                return None

        max_workers = max(1, min(int(workers or 1), 1024))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(scan_tcp_port, port) for port in ports]
            for future in as_completed(futures):
                if should_cancel and should_cancel():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return canceled_response()
                row = future.result()
                if row:
                    open_ports.append(row)

        open_ports.sort(key=lambda item: item["port"])
        tcp_result = {
            "scanned_port_count": len(ports),
            "open_port_count": len(open_ports),
            "open_ports": open_ports,
            "scan_method": "connect",
            "scanner": "builtin",
            "note": "Builtin scanner uses TCP connect and basic service guessing.",
        }
        tcp_result = _attach_suspicious_open_warning(tcp_result, protocol="TCP")

    if udp_scan:
        udp_result = {
            "enabled": False,
            "scanner": "builtin",
            "message": "Builtin scanner does not support UDP probing. Switch to nmap for UDP scan.",
        }

    return tcp_result, udp_result


def _service_to_banner(service: ET.Element) -> str | None:
    parts = []
    for key in ["product", "version", "extrainfo"]:
        value = service.attrib.get(key)
        if value:
            parts.append(value)
    if not parts:
        return None
    return " ".join(parts)


def _service_cpe_list(service: ET.Element) -> list[str]:
    cpes = []
    for cpe_node in service.findall("cpe"):
        text = (cpe_node.text or "").strip()
        if text and text not in cpes:
            cpes.append(text)
    return cpes


def _parse_nmap_xml(xml_text: str, scanned_port_count: int) -> tuple[dict, dict]:
    tcp_open_ports = []
    udp_open_ports = []

    root = ET.fromstring(xml_text)
    for port in root.findall(".//host/ports/port"):
        protocol = port.attrib.get("protocol")
        port_id = port.attrib.get("portid")
        state_node = port.find("state")
        if protocol not in {"tcp", "udp"} or not port_id or state_node is None:
            continue

        state = state_node.attrib.get("state", "unknown")
        if state not in {"open", "open|filtered"}:
            continue

        service = port.find("service")
        service_name = "unknown"
        banner = None
        cpe = []
        if service is not None:
            service_name = service.attrib.get("name", "unknown")
            banner = _service_to_banner(service)
            cpe = _service_cpe_list(service)

        row = {
            "port": int(port_id),
            "protocol": protocol,
            "service": service_name,
            "state": state,
            "banner": banner,
            "cpe": cpe,
        }
        if protocol == "tcp":
            tcp_open_ports.append(row)
        else:
            udp_open_ports.append(row)

    tcp_open_ports.sort(key=lambda item: item["port"])
    udp_open_ports.sort(key=lambda item: item["port"])
    return (
        {
            "scanned_port_count": scanned_port_count,
            "open_port_count": len(tcp_open_ports),
            "open_ports": tcp_open_ports,
            "scanner": "nmap",
        },
        {
            "scanned_port_count": scanned_port_count,
            "open_port_count": len(udp_open_ports),
            "open_ports": udp_open_ports,
            "note": "UDP results may include open|filtered states.",
            "scanner": "nmap",
        },
    )


def _scan_with_nmap(
    ip: str,
    ports: list[int],
    timeout: float,
    tcp_scan: bool,
    udp_scan: bool,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_process_start: Optional[Callable[[subprocess.Popen], None]] = None,
    on_process_end: Optional[Callable[[], None]] = None,
) -> tuple[dict, dict]:
    def canceled_response() -> tuple[dict, dict]:
        message = "Scan canceled by user."
        return (
            {"enabled": False, "canceled": True, "message": message},
            {"enabled": False, "canceled": True, "message": message},
        )

    if should_cancel and should_cancel():
        return canceled_response()

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        message = "nmap is not installed or not in PATH."
        return (
            {"enabled": False, "error": message},
            {"enabled": False, "error": message},
        )

    nmap_port_range = _port_list_to_nmap_range(ports)
    host_timeout_seconds = _estimate_host_timeout_seconds(
        port_count=len(ports),
        timeout_base=timeout,
        udp_scan=udp_scan,
    )

    def run_nmap_once(scan_args: list[str]) -> tuple[str, str, int] | None:
        command = [
            nmap_path,
            "-n",
            "-Pn",
            "--open",
            "-T3",
            "--max-retries",
            "3",
            "--host-timeout",
            f"{host_timeout_seconds}s",
            "-p",
            nmap_port_range,
            "-oX",
            "-",
            *scan_args,
            ip,
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=_build_nmap_env(),
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
                    return None
                time.sleep(0.1)
            completed_stdout, completed_stderr = process.communicate()
            return completed_stdout, completed_stderr, process.returncode
        except Exception as exc:  # noqa: BLE001
            message = f"Failed to execute nmap: {exc}"
            if "argument list too long" in message.lower():
                message = (
                    f"{message}. "
                    "Hint: reduce port range, or use compact ranges like 1-65535 instead of huge explicit lists."
                )
            return "", message, 1
        finally:
            if on_process_end:
                on_process_end()

    if not tcp_scan and not udp_scan:
        message = "Both TCP and UDP scan are disabled."
        return (
            {"enabled": False, "message": message},
            {"enabled": False, "message": message},
        )

    tcp_result: dict = {"enabled": False, "message": "TCP scan disabled."}
    udp_result: dict = {"enabled": False, "message": "UDP scan disabled."}

    if tcp_scan:
        tcp_scan_args, tcp_scan_method = _choose_tcp_scan_args()
        tcp_exec = run_nmap_once(tcp_scan_args)
        if tcp_exec is None:
            return canceled_response()
        tcp_stdout, tcp_stderr, tcp_returncode = tcp_exec

        if tcp_returncode != 0 and not tcp_stdout.strip():
            tcp_result = {
                "enabled": False,
                "scan_method": tcp_scan_method,
                "error": tcp_stderr.strip() or "nmap TCP scan failed.",
            }
        else:
            try:
                tcp_result, _ = _parse_nmap_xml(tcp_stdout, scanned_port_count=len(ports))
                tcp_result["scan_method"] = tcp_scan_method
                tcp_result = _attach_suspicious_open_warning(tcp_result, protocol="TCP")
            except Exception as exc:  # noqa: BLE001
                tcp_result = {
                    "enabled": False,
                    "scan_method": tcp_scan_method,
                    "error": f"Failed to parse nmap TCP XML output: {exc}",
                }

    if udp_scan:
        udp_exec = run_nmap_once(["-sU"])
        if udp_exec is None:
            return canceled_response()
        udp_stdout, udp_stderr, udp_returncode = udp_exec

        if udp_returncode != 0 and not udp_stdout.strip():
            udp_result = {"enabled": False, "error": udp_stderr.strip() or "nmap UDP scan failed."}
        else:
            try:
                _, udp_result = _parse_nmap_xml(udp_stdout, scanned_port_count=len(ports))
                udp_result = _attach_suspicious_open_warning(udp_result, protocol="UDP")
            except Exception as exc:  # noqa: BLE001
                udp_result = {"enabled": False, "error": f"Failed to parse nmap UDP XML output: {exc}"}

    return tcp_result, udp_result


def collect_ip_info(
    target_domain: str,
    dns_result: dict,
    port_range: str = "1-1024",
    timeout: float = 0.8,
    workers: int = 200,
    scanner: str = "auto",
    full_port_scan: bool = False,
    tcp_scan: bool = True,
    udp_scan: bool = False,
    allow_private_ip: bool = False,
    cidr_targets: str = "",
    cidr_host_limit: int = 256,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_process_start: Optional[Callable[[subprocess.Popen], None]] = None,
    on_process_end: Optional[Callable[[], None]] = None,
) -> dict:
    def is_canceled() -> bool:
        return bool(should_cancel and should_cancel())

    requested_scanner = (scanner or "auto").strip().lower()
    if requested_scanner not in {"auto", "nmap", "builtin"}:
        return {
            "enabled": True,
            "scan_performed": False,
            "targets": [],
            "error": f"Invalid scanner: {scanner}. Allowed: auto, nmap, builtin.",
        }

    nmap_available = bool(shutil.which("nmap"))
    if requested_scanner == "nmap":
        scanner_used = "nmap"
    elif requested_scanner == "auto":
        scanner_used = "nmap" if nmap_available else "skipped"
    else:
        scanner_used = "skipped"

    if is_canceled():
        return {
            "enabled": True,
            "scan_performed": False,
            "canceled": True,
            "targets": [],
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "message": "Scan canceled by user.",
        }

    effective_range = "1-65535" if full_port_scan else port_range
    resolved_from_target = _extract_ips(target_domain, dns_result)
    expanded_cidr_hosts, invalid_cidrs, cidr_truncated = _expand_cidr_targets(
        cidr_targets=cidr_targets,
        host_limit_per_cidr=cidr_host_limit,
    )

    ips = []
    seen = set()
    for ip in [*resolved_from_target, *expanded_cidr_hosts]:
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    if not ips:
        return {
            "enabled": True,
            "scan_performed": False,
            "targets": [],
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "invalid_cidrs": invalid_cidrs,
            "cidr_expansion_truncated": cidr_truncated,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "skip_reason": "No IP addresses were resolved from the target.",
            "message": "No IP addresses found for port scanning.",
        }

    if allow_private_ip:
        candidate_ips = ips
        skipped_non_public_ips = []
    else:
        candidate_ips = [ip for ip in ips if _is_real_public_ip(ip)]
        skipped_non_public_ips = [ip for ip in ips if ip not in candidate_ips]

    if not candidate_ips:
        return {
            "enabled": True,
            "scan_performed": False,
            "targets": [],
            "resolved_ips": ips,
            "resolved_from_target": resolved_from_target,
            "resolved_from_cidr": expanded_cidr_hosts,
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "invalid_cidrs": invalid_cidrs,
            "cidr_expansion_truncated": cidr_truncated,
            "skipped_non_public_ips": skipped_non_public_ips,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "skip_reason": "No real public IP addresses were resolved from the target.",
            "message": "No real public IP addresses found for port scanning. Enable allow_private_ip to include private ranges.",
        }

    if not tcp_scan and not udp_scan:
        return {
            "enabled": True,
            "scan_performed": False,
            "targets": candidate_ips,
            "resolved_ips": ips,
            "resolved_from_target": resolved_from_target,
            "resolved_from_cidr": expanded_cidr_hosts,
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "invalid_cidrs": invalid_cidrs,
            "cidr_expansion_truncated": cidr_truncated,
            "skipped_non_public_ips": skipped_non_public_ips,
            "full_port_scan": full_port_scan,
            "port_range": effective_range,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "scan_timeout_seconds": timeout,
            "workers": workers,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "skip_reason": "Both TCP and UDP scan are disabled.",
            "message": "No protocol selected. Enable TCP and/or UDP scan.",
        }

    if scanner_used != "nmap":
        if requested_scanner == "builtin":
            skip_reason = "Port scan skipped because this project now requires nmap for port scanning."
            message = "Builtin scanner is disabled. Install nmap or switch the port scan module off."
        else:
            skip_reason = "Port scan skipped because nmap is not installed or not in PATH."
            message = "nmap not found. Port scan has been skipped."

        return {
            "enabled": True,
            "scan_performed": False,
            "targets": candidate_ips,
            "resolved_ips": ips,
            "resolved_from_target": resolved_from_target,
            "resolved_from_cidr": expanded_cidr_hosts,
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "invalid_cidrs": invalid_cidrs,
            "cidr_expansion_truncated": cidr_truncated,
            "skipped_non_public_ips": skipped_non_public_ips,
            "full_port_scan": full_port_scan,
            "port_range": effective_range,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "scan_timeout_seconds": timeout,
            "workers": workers,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "skip_reason": skip_reason,
            "message": message,
        }

    try:
        ports = _parse_ports(effective_range)
    except Exception as exc:  # noqa: BLE001
        return {
            "enabled": True,
            "scan_performed": False,
            "targets": candidate_ips,
            "resolved_ips": ips,
            "resolved_from_target": resolved_from_target,
            "resolved_from_cidr": expanded_cidr_hosts,
            "allow_private_ip": allow_private_ip,
            "cidr_targets": cidr_targets,
            "invalid_cidrs": invalid_cidrs,
            "cidr_expansion_truncated": cidr_truncated,
            "skipped_non_public_ips": skipped_non_public_ips,
            "tcp_scan_enabled": tcp_scan,
            "udp_scan_enabled": udp_scan,
            "requested_scanner": requested_scanner,
            "scanner": scanner_used,
            "error": f"Invalid port range: {exc}",
        }

    scan_warnings = []
    if scanner_used == "builtin" and udp_scan:
        scan_warnings.append("Builtin scanner does not support UDP probing. UDP scan results will be disabled.")

    results = {}
    for ip in candidate_ips:
        if is_canceled():
            return {
                "enabled": True,
                "scan_performed": False,
                "canceled": True,
                "targets": candidate_ips,
                "resolved_ips": ips,
                "resolved_from_target": resolved_from_target,
                "resolved_from_cidr": expanded_cidr_hosts,
                "allow_private_ip": allow_private_ip,
                "cidr_targets": cidr_targets,
                "invalid_cidrs": invalid_cidrs,
                "cidr_expansion_truncated": cidr_truncated,
                "skipped_non_public_ips": skipped_non_public_ips,
                "full_port_scan": full_port_scan,
                "port_range": effective_range,
                "tcp_scan_enabled": tcp_scan,
                "udp_scan_enabled": udp_scan,
                "scan_timeout_seconds": timeout,
                "workers": workers,
                "requested_scanner": requested_scanner,
                "scanner": scanner_used,
                "results": results,
                "message": "Scan canceled by user.",
            }

        if scanner_used == "nmap":
            tcp_result, udp_result = _scan_with_nmap(
                ip=ip,
                ports=ports,
                timeout=timeout,
                tcp_scan=tcp_scan,
                udp_scan=udp_scan,
                should_cancel=should_cancel,
                on_process_start=on_process_start,
                on_process_end=on_process_end,
            )
        else:
            tcp_result, udp_result = _scan_with_builtin_socket(
                ip=ip,
                ports=ports,
                timeout=timeout,
                workers=workers,
                tcp_scan=tcp_scan,
                udp_scan=udp_scan,
                should_cancel=should_cancel,
            )

        results[ip] = {
            "tcp": tcp_result,
            "udp": udp_result,
        }

    return {
        "enabled": True,
        "scan_performed": True,
        "targets": candidate_ips,
        "resolved_ips": ips,
        "resolved_from_target": resolved_from_target,
        "resolved_from_cidr": expanded_cidr_hosts,
        "allow_private_ip": allow_private_ip,
        "cidr_targets": cidr_targets,
        "invalid_cidrs": invalid_cidrs,
        "cidr_expansion_truncated": cidr_truncated,
        "skipped_non_public_ips": skipped_non_public_ips,
        "full_port_scan": full_port_scan,
        "port_range": effective_range,
        "tcp_scan_enabled": tcp_scan,
        "udp_scan_enabled": udp_scan,
        "scan_timeout_seconds": timeout,
        "workers": workers,
        "requested_scanner": requested_scanner,
        "scanner": scanner_used,
        "warnings": scan_warnings,
        "results": results,
    }
