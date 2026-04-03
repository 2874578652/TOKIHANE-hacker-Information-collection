import whois


def _normalize_value(value):
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return None
    return str(value)


def collect_whois(domain: str) -> dict:
    try:
        data = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    if not data:
        return {"error": "No WHOIS data returned."}

    keys = [
        "domain_name",
        "registrar",
        "whois_server",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name_servers",
        "status",
        "emails",
        "dnssec",
    ]
    normalized = {}
    for key in keys:
        normalized[key] = _normalize_value(data.get(key))
    return normalized
