from datetime import datetime, timezone
import os
import subprocess
import threading
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.collector import collect_information
from core.env_loader import load_env_file

COMMON_PORT_RANGE = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,1723,1883,1900,2049,2375,2376,3306,3389,5432,5900,6379,7001,8000,8080,8081,8443,8888,9200,11211,27017"


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, URL, or IP")
    timeout: int = Field(default=10, ge=1, le=300)
    port_range: str = Field(default="1-1024")
    port_timeout: float = Field(default=0.8, ge=0.05, le=60)
    port_workers: int = Field(default=200, ge=1, le=2000)
    port_scanner: str = Field(
        default="auto",
        description="Port scanner backend: auto / nmap / builtin (builtin is accepted for compatibility but skipped).",
    )
    full_port_scan: bool = Field(default=True)
    tcp_scan: bool = Field(default=True)
    udp_scan: bool = Field(default=True)
    vt_scan: bool = Field(default=False)
    vt_api_key: str | None = Field(default=None)
    nvd_api_key: str | None = Field(default=None)
    allow_private_ip: bool = Field(default=False)
    cidr_targets: str = Field(default="", description="Optional CIDR targets, comma separated.")
    ct_scan: bool = Field(default=False)
    passive_dns_scan: bool = Field(default=False)
    asn_scan: bool = Field(default=False)
    asn_expand_c_segment: bool = Field(default=False)
    web_asset_scan: bool = Field(default=False)
    web_crawler: bool = Field(default=True)
    web_js_extract: bool = Field(default=True)
    web_sensitive_path_extract: bool = Field(default=True)
    web_dir_scan: bool = Field(default=True)
    web_dir_use_ffuf: bool = Field(default=False)
    service_risk_scan: bool = Field(default=False)
    cve_lookup: bool = Field(default=False)
    weak_nmap_checks: bool = Field(default=False)
    scan_mode: str | None = Field(
        default=None,
        description="Port scan mode: common / full / custom (optional, for frontend mode selector).",
    )
    custom_ports: str | None = Field(
        default=None,
        description="Custom ports when scan_mode=custom, e.g. 22,80,443,3306",
    )


class ScanJob:
    def __init__(self, payload: ScanRequest):
        self.id = str(uuid.uuid4())
        self.payload = payload
        self.status = "queued"
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.result: Optional[dict[str, Any]] = None
        self.error: Optional[str] = None
        self.stop_event = threading.Event()
        self.nmap_process: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None

    def set_process(self, proc: subprocess.Popen) -> None:
        with self.lock:
            self.nmap_process = proc

    def clear_process(self) -> None:
        with self.lock:
            self.nmap_process = None

    def request_stop(self) -> None:
        self.stop_event.set()
        with self.lock:
            proc = self.nmap_process
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass

    def should_cancel(self) -> bool:
        return self.stop_event.is_set()


load_env_file(".env")
app = FastAPI(title="TOKIHANE Recon API", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

jobs: dict[str, ScanJob] = {}
jobs_lock = threading.Lock()


def _run_scan_job(job: ScanJob) -> None:
    job.status = "running"
    job.started_at = datetime.now(timezone.utc).isoformat()
    payload = job.payload

    vt_api_key = (payload.vt_api_key or "").strip()
    nvd_api_key = payload.nvd_api_key if payload.nvd_api_key else os.getenv("NVD_API_KEY")
    requested_mode = (payload.scan_mode or "").strip().lower()
    requested_scanner = (payload.port_scanner or "auto").strip().lower()
    scan_mode_used = "legacy"
    full_port_scan = payload.full_port_scan
    port_range = payload.port_range

    if requested_mode == "common":
        full_port_scan = False
        port_range = COMMON_PORT_RANGE
        scan_mode_used = "common"
    elif requested_mode == "full":
        full_port_scan = True
        port_range = "1-65535"
        scan_mode_used = "full"
    elif requested_mode == "custom":
        custom_ports = (payload.custom_ports or "").strip()
        if not custom_ports:
            job.error = "custom_ports cannot be empty when scan_mode=custom"
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc).isoformat()
            return
        full_port_scan = False
        port_range = custom_ports
        scan_mode_used = "custom"
    elif requested_mode:
        job.error = f"Invalid scan_mode: {payload.scan_mode}. Allowed: common, full, custom."
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        return

    if requested_scanner not in {"auto", "nmap", "builtin"}:
        job.error = f"Invalid port_scanner: {payload.port_scanner}. Allowed: auto, nmap, builtin."
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        return

    if payload.vt_scan and not vt_api_key:
        job.error = "VirusTotal is enabled, but vt_api_key is empty. Please provide your own API key."
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        return

    try:
        report = collect_information(
            target=payload.target,
            timeout=payload.timeout,
            vt_api_key=vt_api_key,
            vt_scan=payload.vt_scan,
            port_range=port_range,
            port_timeout=payload.port_timeout,
            port_workers=payload.port_workers,
            port_scanner=requested_scanner,
            full_port_scan=full_port_scan,
            tcp_scan=payload.tcp_scan,
            udp_scan=payload.udp_scan,
            allow_private_ip=payload.allow_private_ip,
            cidr_targets=payload.cidr_targets,
            ct_scan=payload.ct_scan,
            passive_dns_scan=payload.passive_dns_scan,
            asn_scan=payload.asn_scan,
            asn_expand_c_segment=payload.asn_expand_c_segment,
            web_asset_scan=payload.web_asset_scan,
            web_crawler=payload.web_crawler,
            web_js_extract=payload.web_js_extract,
            web_sensitive_path_extract=payload.web_sensitive_path_extract,
            web_dir_scan=payload.web_dir_scan,
            web_dir_use_ffuf=payload.web_dir_use_ffuf,
            service_risk_scan=payload.service_risk_scan,
            cve_lookup=payload.cve_lookup,
            weak_nmap_checks=payload.weak_nmap_checks,
            nvd_api_key=nvd_api_key,
            should_cancel=job.should_cancel,
            on_process_start=job.set_process,
            on_process_end=job.clear_process,
        )
        report["meta"] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_input": payload.target,
            "job_id": job.id,
            "scan_mode": scan_mode_used,
            "requested_port_range": port_range,
            "requested_port_scanner": requested_scanner,
            "vt_scan_enabled": payload.vt_scan,
            "allow_private_ip": payload.allow_private_ip,
            "cidr_targets": payload.cidr_targets,
            "ct_scan_enabled": payload.ct_scan,
            "passive_dns_scan_enabled": payload.passive_dns_scan,
            "asn_scan_enabled": payload.asn_scan,
            "asn_expand_c_segment_enabled": payload.asn_expand_c_segment,
            "web_asset_scan_enabled": payload.web_asset_scan,
            "web_crawler_enabled": payload.web_crawler,
            "web_js_extract_enabled": payload.web_js_extract,
            "web_sensitive_path_extract_enabled": payload.web_sensitive_path_extract,
            "web_dir_scan_enabled": payload.web_dir_scan,
            "web_dir_use_ffuf_enabled": payload.web_dir_use_ffuf,
            "service_risk_scan_enabled": payload.service_risk_scan,
            "cve_lookup_enabled": payload.cve_lookup,
            "weak_nmap_checks_enabled": payload.weak_nmap_checks,
        }
        job.result = report

        if job.should_cancel() or bool(report.get("canceled")):
            job.status = "canceled"
        else:
            job.status = "completed"
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc)
        job.status = "failed"
    finally:
        job.clear_process()
        job.finished_at = datetime.now(timezone.utc).isoformat()


def _job_response(job: ScanJob) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "result": job.result,
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/scan")
def create_scan(payload: ScanRequest) -> dict[str, Any]:
    job = ScanJob(payload)
    thread = threading.Thread(target=_run_scan_job, args=(job,), daemon=True)
    job.thread = thread

    with jobs_lock:
        jobs[job.id] = job

    thread.start()
    return {
        "job_id": job.id,
        "status": "queued",
        "created_at": job.created_at,
    }


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str) -> dict[str, Any]:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_response(job)


@app.post("/api/scan/{job_id}/stop")
def stop_scan(job_id: str) -> dict[str, Any]:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status in {"completed", "failed", "canceled"}:
        return {
            "job_id": job.id,
            "status": job.status,
            "message": "Job already finished.",
        }

    job.status = "stopping"
    job.request_stop()
    return {
        "job_id": job.id,
        "status": "stopping",
        "message": "Stop signal sent.",
    }


@app.get("/api/jobs")
def list_jobs() -> dict[str, Any]:
    with jobs_lock:
        ordered = sorted(jobs.values(), key=lambda item: item.created_at, reverse=True)
    return {"jobs": [_job_response(job) for job in ordered]}
