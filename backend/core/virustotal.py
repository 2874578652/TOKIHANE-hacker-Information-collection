import base64

import requests


VT_DOMAIN_ENDPOINT = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"


def _encode_url_for_vt(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return encoded.strip("=")


def _parse_common_stats(payload: dict) -> dict:
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "last_analysis_stats": stats,
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
    }


def _build_vt_result(resp: requests.Response) -> dict:
    result = {"status_code": resp.status_code}

    if not resp.content:
        return result

    try:
        payload = resp.json()
    except ValueError:
        result["raw_response_text"] = resp.text
        return result

    result.update(_parse_common_stats(payload))
    # Keep the full VirusTotal payload for complete output/export use cases.
    result["full_result"] = payload
    return result


def query_virustotal(domain: str, normalized_url: str, api_key: str, timeout: int = 10) -> dict:
    if not api_key:
        return {"enabled": False, "message": "VirusTotal API key not provided."}

    headers = {"x-apikey": api_key}
    result = {"enabled": True}

    domain_url = VT_DOMAIN_ENDPOINT.format(domain=domain)
    try:
        domain_resp = requests.get(domain_url, headers=headers, timeout=timeout)
        result["domain"] = _build_vt_result(domain_resp)
    except Exception as exc:  # noqa: BLE001
        result["domain"] = {"error": str(exc)}

    try:
        url_id = _encode_url_for_vt(normalized_url)
        url_resp = requests.get(VT_URL_ENDPOINT.format(url_id=url_id), headers=headers, timeout=timeout)
        result["url"] = _build_vt_result(url_resp)
    except Exception as exc:  # noqa: BLE001
        result["url"] = {"error": str(exc)}

    return result
