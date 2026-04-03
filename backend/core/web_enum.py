import re
import shutil
import subprocess
import tempfile
import os
from collections import deque
from typing import Callable, Optional
from urllib.parse import urljoin, urldefrag, urlparse

import requests
from bs4 import BeautifulSoup


DEFAULT_HEADERS = {
    "User-Agent": "TOKIHANE-Recon/1.0 (+https://localhost)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

DEFAULT_DIR_WORDLIST = [
    "admin",
    "administrator",
    "login",
    "signin",
    "dashboard",
    "console",
    "api",
    "api/v1",
    "api/v2",
    ".env",
    ".git/config",
    "config",
    "backup",
    "uploads",
    "upload",
    "phpinfo.php",
    "swagger",
    "swagger-ui",
    "swagger-ui.html",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    "actuator",
    "metrics",
    "debug",
    "health",
    "status",
]

STATIC_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".bmp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".avi",
    ".mov",
    ".mp3",
    ".wav",
    ".zip",
    ".rar",
    ".7z",
    ".pdf",
)

SENSITIVE_PATH_REGEX = re.compile(
    r"(?i)(?:/|^)(?:admin|backup|config|debug|internal|private|secret|test|staging|dev|swagger|actuator|metrics|graphql)"
)

JS_ENDPOINT_REGEX = re.compile(
    r"""(?:"|')(
    /[a-zA-Z0-9_\-./?=&%]+
    )(?:\"|')""",
    re.VERBOSE,
)


def _normalize_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.scheme:
        base_url = f"http://{base_url}"
        parsed = urlparse(base_url)
    if not parsed.path:
        return f"{base_url.rstrip('/')}/"
    return base_url


def _is_same_scope(candidate_url: str, base_host: str) -> bool:
    parsed = urlparse(candidate_url)
    return parsed.scheme in {"http", "https"} and parsed.hostname == base_host


def _is_static_resource(path: str) -> bool:
    lowered = (path or "").lower()
    return lowered.endswith(STATIC_SUFFIXES)


def _extract_html_links(html: str, current_url: str) -> tuple[list[str], list[str]]:
    links = []
    js_files = []
    soup = BeautifulSoup(html, "html.parser")

    for tag, attr in [("a", "href"), ("link", "href"), ("form", "action"), ("iframe", "src")]:
        for node in soup.find_all(tag):
            raw = str(node.get(attr, "")).strip()
            if not raw:
                continue
            if raw.startswith(("mailto:", "javascript:", "#")):
                continue
            absolute = urljoin(current_url, raw)
            absolute, _ = urldefrag(absolute)
            links.append(absolute)

    for script in soup.find_all("script"):
        src = str(script.get("src", "")).strip()
        if src:
            absolute = urljoin(current_url, src)
            absolute, _ = urldefrag(absolute)
            js_files.append(absolute)

    return links, js_files


def _extract_js_endpoints(text: str) -> list[str]:
    found = []
    for match in JS_ENDPOINT_REGEX.findall(text or ""):
        path = match.strip()
        if len(path) < 2 or len(path) > 200:
            continue
        if path.startswith("//"):
            continue
        found.append(path)
    return sorted(set(found))


def _request_text(url: str, timeout: int) -> tuple[int | None, str | None, str | None]:
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc)
    content_type = str(response.headers.get("Content-Type", "")).lower()
    text = response.text if "text" in content_type or "json" in content_type or "javascript" in content_type else ""
    return response.status_code, text, None


def _run_crawler(
    base_url: str,
    timeout: int = 10,
    max_pages: int = 30,
    max_depth: int = 2,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    normalized = _normalize_url(base_url)
    host = urlparse(normalized).hostname or ""
    queue = deque([(normalized, 0)])
    visited = set()
    pages = []
    js_files = set()
    discovered_endpoints = set()
    sensitive_hits = set()

    while queue and len(visited) < max_pages:
        if should_cancel and should_cancel():
            return {
                "enabled": True,
                "canceled": True,
                "message": "Crawler canceled by user.",
                "pages": pages,
                "js_files": sorted(js_files),
                "discovered_endpoints": sorted(discovered_endpoints),
                "sensitive_paths": sorted(sensitive_hits),
            }

        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        status_code, text, error = _request_text(current_url, timeout=timeout)
        page_entry = {"url": current_url, "depth": depth, "status_code": status_code}
        if error:
            page_entry["error"] = error
            pages.append(page_entry)
            continue

        pages.append(page_entry)
        if not text:
            continue

        links, script_urls = _extract_html_links(text, current_url)
        js_files.update(script_urls)
        discovered_endpoints.update(_extract_js_endpoints(text))

        for link in links:
            parsed = urlparse(link)
            if not _is_same_scope(link, host):
                continue
            if _is_static_resource(parsed.path):
                continue
            if SENSITIVE_PATH_REGEX.search(parsed.path or ""):
                sensitive_hits.add(link)
            if link not in visited:
                queue.append((link, depth + 1))

    return {
        "enabled": True,
        "base_url": normalized,
        "page_count": len(pages),
        "pages": pages,
        "js_files": sorted(js_files),
        "discovered_endpoints": sorted(discovered_endpoints),
        "sensitive_paths": sorted(sensitive_hits),
    }


def _probe_with_builtin(base_url: str, timeout: int, words: list[str], should_cancel: Optional[Callable[[], bool]] = None) -> dict:
    normalized = _normalize_url(base_url)
    hits = []
    for word in words:
        if should_cancel and should_cancel():
            return {
                "enabled": True,
                "scanner": "builtin",
                "canceled": True,
                "hits": hits,
                "message": "Directory probing canceled by user.",
            }
        target = urljoin(normalized, word)
        try:
            response = requests.get(
                target,
                headers=DEFAULT_HEADERS,
                timeout=timeout,
                allow_redirects=False,
            )
        except Exception:
            continue

        if response.status_code in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}:
            hits.append(
                {
                    "url": target,
                    "status_code": response.status_code,
                    "length": len(response.text or ""),
                    "content_type": response.headers.get("Content-Type"),
                    "location": response.headers.get("Location"),
                }
            )
    return {
        "enabled": True,
        "scanner": "builtin",
        "word_count": len(words),
        "hit_count": len(hits),
        "hits": hits,
    }


def _probe_with_ffuf(base_url: str, timeout: int, words: list[str]) -> dict:
    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        return {"enabled": False, "error": "ffuf not found in PATH. Falling back to builtin probing."}

    normalized = _normalize_url(base_url)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as word_file:
        word_file.write("\n".join(words))
        wordlist_path = word_file.name

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as result_file:
        result_path = result_file.name

    cmd = [
        ffuf_bin,
        "-w",
        wordlist_path,
        "-u",
        f"{normalized}FUZZ",
        "-of",
        "json",
        "-o",
        result_path,
        "-timeout",
        str(max(1, int(timeout))),
        "-t",
        "40",
        "-mc",
        "200,201,202,204,301,302,307,308,401,403",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode not in {0}:
            return {"enabled": False, "error": proc.stderr.strip() or "ffuf failed."}

        try:
            with open(result_path, "r", encoding="utf-8") as f:
                import json

                payload = json.load(f)
        except Exception as exc:  # noqa: BLE001
            return {"enabled": False, "error": f"Failed to parse ffuf output: {exc}"}

        results = []
        for row in payload.get("results", [])[:1000]:
            results.append(
                {
                    "url": row.get("url"),
                    "status_code": row.get("status"),
                    "length": row.get("length"),
                    "words": row.get("words"),
                    "lines": row.get("lines"),
                    "redirectlocation": row.get("redirectlocation"),
                }
            )

        return {
            "enabled": True,
            "scanner": "ffuf",
            "word_count": len(words),
            "hit_count": len(results),
            "hits": results,
        }
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": f"Failed to execute ffuf: {exc}"}
    finally:
        for path in [wordlist_path, result_path]:
            try:
                os.remove(path)
            except Exception:
                pass


def _extract_from_js_files(
    js_urls: list[str],
    timeout: int,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    endpoints = set()
    sensitive_paths = set()
    samples = []

    for js_url in js_urls[:200]:
        if should_cancel and should_cancel():
            return {
                "enabled": True,
                "canceled": True,
                "message": "JS extraction canceled by user.",
                "endpoints": sorted(endpoints),
                "sensitive_paths": sorted(sensitive_paths),
                "samples": samples,
            }
        status_code, text, error = _request_text(js_url, timeout=timeout)
        if error or not text:
            continue
        extracted = _extract_js_endpoints(text)
        for endpoint in extracted:
            endpoints.add(endpoint)
            if SENSITIVE_PATH_REGEX.search(endpoint):
                sensitive_paths.add(endpoint)
        if extracted and len(samples) < 100:
            samples.append({"js_url": js_url, "status_code": status_code, "endpoint_count": len(extracted)})

    return {
        "enabled": True,
        "endpoints": sorted(endpoints),
        "sensitive_paths": sorted(sensitive_paths),
        "samples": samples,
    }


def collect_web_assets(
    normalized_url: str,
    timeout: int = 10,
    web_crawler: bool = True,
    web_js_extract: bool = True,
    web_sensitive_path_extract: bool = True,
    web_dir_scan: bool = True,
    web_dir_use_ffuf: bool = False,
    dir_wordlist: Optional[list[str]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    result: dict = {"enabled": True, "base_url": _normalize_url(normalized_url)}
    crawler_result = {
        "enabled": False,
        "message": "Crawler disabled by user.",
        "js_files": [],
        "discovered_endpoints": [],
        "sensitive_paths": [],
    }

    if web_crawler:
        crawler_result = _run_crawler(
            base_url=normalized_url,
            timeout=timeout,
            max_pages=40,
            max_depth=2,
            should_cancel=should_cancel,
        )
    result["crawler"] = crawler_result

    if should_cancel and should_cancel():
        result["canceled"] = True
        result["message"] = "Web asset collection canceled by user."
        return result

    js_result = {"enabled": False, "message": "JS endpoint extraction disabled by user."}
    if web_js_extract:
        js_sources = crawler_result.get("js_files", []) if isinstance(crawler_result, dict) else []
        js_result = _extract_from_js_files(
            js_urls=js_sources,
            timeout=timeout,
            should_cancel=should_cancel,
        )
    result["js_extraction"] = js_result

    if should_cancel and should_cancel():
        result["canceled"] = True
        result["message"] = "Web asset collection canceled by user."
        return result

    words = dir_wordlist or DEFAULT_DIR_WORDLIST
    dir_result = {"enabled": False, "message": "Directory probing disabled by user."}
    if web_dir_scan:
        if web_dir_use_ffuf:
            ffuf_result = _probe_with_ffuf(
                base_url=normalized_url,
                timeout=timeout,
                words=words,
            )
            if ffuf_result.get("enabled"):
                dir_result = ffuf_result
            else:
                fallback = _probe_with_builtin(
                    base_url=normalized_url,
                    timeout=timeout,
                    words=words,
                    should_cancel=should_cancel,
                )
                fallback["ffuf_fallback_reason"] = ffuf_result.get("error")
                dir_result = fallback
        else:
            dir_result = _probe_with_builtin(
                base_url=normalized_url,
                timeout=timeout,
                words=words,
                should_cancel=should_cancel,
            )
    result["directory_probe"] = dir_result

    merged_sensitive = set()
    if web_sensitive_path_extract:
        for value in crawler_result.get("sensitive_paths", []):
            merged_sensitive.add(value)
        for value in js_result.get("sensitive_paths", []):
            merged_sensitive.add(value)
        for row in dir_result.get("hits", []):
            if not isinstance(row, dict):
                continue
            url = str(row.get("url", ""))
            if SENSITIVE_PATH_REGEX.search(url):
                merged_sensitive.add(url)
        result["sensitive_paths"] = {
            "enabled": True,
            "count": len(merged_sensitive),
            "items": sorted(merged_sensitive),
        }
    else:
        result["sensitive_paths"] = {
            "enabled": False,
            "message": "Sensitive path extraction disabled by user.",
        }

    combined_endpoints = set()
    for endpoint in crawler_result.get("discovered_endpoints", []):
        combined_endpoints.add(endpoint)
    for endpoint in js_result.get("endpoints", []):
        combined_endpoints.add(endpoint)
    result["combined_endpoints"] = sorted(combined_endpoints)

    return result
