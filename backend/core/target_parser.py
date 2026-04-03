from urllib.parse import urlparse


def parse_target(target: str) -> dict:
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")

    has_scheme = "://" in cleaned
    raw_url = cleaned if has_scheme else f"http://{cleaned}"
    parsed = urlparse(raw_url)

    if not parsed.hostname:
        raise ValueError(f"Unable to parse domain from target: {target}")

    normalized_url = raw_url
    if not parsed.path:
        normalized_url = f"{raw_url.rstrip('/')}/"

    return {
        "input": target,
        "domain": parsed.hostname,
        "scheme": parsed.scheme,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "normalized_url": normalized_url,
    }
