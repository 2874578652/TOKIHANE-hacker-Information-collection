import argparse
import json
import os
import sys
from datetime import datetime, timezone

from core.env_loader import load_env_file
from exporters.json_exporter import export_json
from exporters.txt_exporter import export_txt

COMMON_PORT_RANGE = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,1723,1883,1900,2049,2375,2376,3306,3389,5432,5900,6379,7001,8000,8080,8081,8443,8888,9200,11211,27017"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect reconnaissance information for a target domain or URL."
    )
    parser.add_argument("target", help="Target domain or URL, e.g. example.com or https://example.com")
    parser.add_argument("--json", dest="json_output", help="Path to JSON output file")
    parser.add_argument("--txt", dest="txt_output", help="Path to TXT output file")
    parser.add_argument(
        "--vt-api-key",
        dest="vt_api_key",
        default="",
        help="Your own VirusTotal API key. Required when VT scan is enabled.",
    )
    parser.add_argument(
        "--nvd-api-key",
        dest="nvd_api_key",
        default=os.getenv("NVD_API_KEY"),
        help="NVD API key (optional, used for CPE/CVE lookup). Priority: --nvd-api-key > NVD_API_KEY (.env supported).",
    )
    parser.add_argument(
        "--vt-scan",
        action=argparse.BooleanOptionalAction,
        dest="vt_scan",
        default=False,
        help="Enable/disable VirusTotal scan (enabled requires --vt-api-key).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP/DNS request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--port-range",
        default="1-1024",
        help="TCP/UDP port range for IP scan, e.g. 1-1024 or 22,80,443 (default: 1-1024)",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=0.8,
        help="TCP connect timeout per port in seconds for IP scan (default: 0.8)",
    )
    parser.add_argument(
        "--port-workers",
        type=int,
        default=200,
        help="Concurrent workers for TCP port scan (default: 200)",
    )
    parser.add_argument(
        "--port-scanner",
        choices=["auto", "nmap", "builtin"],
        default="auto",
        help="Port scan backend: auto (run only when nmap is available), nmap, builtin (accepted but skipped).",
    )
    parser.add_argument(
        "--no-full-port-scan",
        action="store_false",
        dest="full_port_scan",
        default=True,
        help="Disable full TCP/UDP scan range 1-65535",
    )
    parser.add_argument(
        "--no-tcp-scan",
        action="store_false",
        dest="tcp_scan",
        default=True,
        help="Disable TCP scan",
    )
    parser.add_argument(
        "--no-udp-scan",
        action="store_false",
        dest="udp_scan",
        default=True,
        help="Disable UDP scan",
    )
    parser.add_argument(
        "--allow-private-ip",
        action="store_true",
        default=False,
        help="Allow private/internal IPs for port scanning (default: only public IPs).",
    )
    parser.add_argument(
        "--cidr-targets",
        default="",
        help="Extra CIDR targets (comma separated), e.g. 192.168.1.0/24,10.0.0.0/24",
    )
    parser.add_argument(
        "--scan-mode",
        choices=["common", "full", "custom"],
        help="Port scan mode: common (preset ports), full (1-65535), custom (use --custom-ports).",
    )
    parser.add_argument(
        "--custom-ports",
        help="Custom ports/ranges when --scan-mode custom, e.g. 22,80,443,3306 or 1-1024",
    )
    parser.add_argument(
        "--ct-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable certificate transparency collection.",
    )
    parser.add_argument(
        "--passive-dns-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable passive/historical DNS collection.",
    )
    parser.add_argument(
        "--asn-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable ASN and network intel collection.",
    )
    parser.add_argument(
        "--asn-expand-c-segment",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable same C-segment host expansion when ASN scan is on.",
    )
    parser.add_argument(
        "--web-asset-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable web asset enumeration module.",
    )
    parser.add_argument(
        "--web-crawler",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable web crawler (used when web asset scan is enabled).",
    )
    parser.add_argument(
        "--web-js-extract",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable JS endpoint extraction (used when web asset scan is enabled).",
    )
    parser.add_argument(
        "--web-sensitive-path-extract",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable sensitive path extraction (used when web asset scan is enabled).",
    )
    parser.add_argument(
        "--web-dir-scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable web directory/file probing (used when web asset scan is enabled).",
    )
    parser.add_argument(
        "--web-dir-use-ffuf",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable ffuf for directory probing (fallback to builtin probing if ffuf unavailable).",
    )
    parser.add_argument(
        "--service-risk-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable service risk correlation module.",
    )
    parser.add_argument(
        "--cve-lookup",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable CPE to CVE lookup (used when service risk scan is enabled).",
    )
    parser.add_argument(
        "--weak-nmap-checks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable/disable weak configuration checks via nmap NSE (used when service risk scan is enabled).",
    )
    return parser


def main() -> int:
    load_env_file(".env")
    parser = build_parser()
    args = parser.parse_args()

    scan_mode_used = "legacy"
    vt_api_key = (args.vt_api_key or "").strip()
    full_port_scan = args.full_port_scan
    port_range = args.port_range
    if args.scan_mode == "common":
        scan_mode_used = "common"
        full_port_scan = False
        port_range = COMMON_PORT_RANGE
    elif args.scan_mode == "full":
        scan_mode_used = "full"
        full_port_scan = True
        port_range = "1-65535"
    elif args.scan_mode == "custom":
        scan_mode_used = "custom"
        custom_ports = (args.custom_ports or "").strip()
        if not custom_ports:
            parser.error("--custom-ports is required when --scan-mode custom")
        full_port_scan = False
        port_range = custom_ports

    if args.vt_scan and not vt_api_key:
        parser.error("VirusTotal scan is enabled. Please provide your own key via --vt-api-key, or disable VT with --no-vt-scan.")

    from core.collector import collect_information

    report = collect_information(
        target=args.target,
        timeout=args.timeout,
        vt_api_key=vt_api_key,
        vt_scan=args.vt_scan,
        nvd_api_key=args.nvd_api_key,
        port_range=port_range,
        port_timeout=args.port_timeout,
        port_workers=args.port_workers,
        port_scanner=args.port_scanner,
        full_port_scan=full_port_scan,
        tcp_scan=args.tcp_scan,
        udp_scan=args.udp_scan,
        allow_private_ip=args.allow_private_ip,
        cidr_targets=args.cidr_targets,
        ct_scan=args.ct_scan,
        passive_dns_scan=args.passive_dns_scan,
        asn_scan=args.asn_scan,
        asn_expand_c_segment=args.asn_expand_c_segment,
        web_asset_scan=args.web_asset_scan,
        web_crawler=args.web_crawler,
        web_js_extract=args.web_js_extract,
        web_sensitive_path_extract=args.web_sensitive_path_extract,
        web_dir_scan=args.web_dir_scan,
        web_dir_use_ffuf=args.web_dir_use_ffuf,
        service_risk_scan=args.service_risk_scan,
        cve_lookup=args.cve_lookup,
        weak_nmap_checks=args.weak_nmap_checks,
    )
    report["meta"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_input": args.target,
        "scan_mode": scan_mode_used,
        "requested_port_range": port_range,
        "requested_port_scanner": args.port_scanner,
        "vt_scan_enabled": args.vt_scan,
        "allow_private_ip": args.allow_private_ip,
        "cidr_targets": args.cidr_targets,
        "ct_scan_enabled": args.ct_scan,
        "passive_dns_scan_enabled": args.passive_dns_scan,
        "asn_scan_enabled": args.asn_scan,
        "asn_expand_c_segment_enabled": args.asn_expand_c_segment,
        "web_asset_scan_enabled": args.web_asset_scan,
        "web_crawler_enabled": args.web_crawler,
        "web_js_extract_enabled": args.web_js_extract,
        "web_sensitive_path_extract_enabled": args.web_sensitive_path_extract,
        "web_dir_scan_enabled": args.web_dir_scan,
        "web_dir_use_ffuf_enabled": args.web_dir_use_ffuf,
        "service_risk_scan_enabled": args.service_risk_scan,
        "cve_lookup_enabled": args.cve_lookup,
        "weak_nmap_checks_enabled": args.weak_nmap_checks,
    }

    if args.json_output:
        export_json(report, args.json_output)
        print(f"[+] JSON report saved to: {args.json_output}")

    if args.txt_output:
        export_txt(report, args.txt_output)
        print(f"[+] TXT report saved to: {args.txt_output}")

    if not args.json_output and not args.txt_output:
        print(json.dumps(report, indent=2, ensure_ascii=False))

    has_error = any(key == "error" for key in report.keys())
    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
