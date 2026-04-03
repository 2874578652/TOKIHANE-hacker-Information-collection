import dns.resolver


DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def collect_dns(domain: str, timeout: int = 10) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    results = {}
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [str(answer).strip('"') for answer in answers]
        except Exception as exc:  # noqa: BLE001
            results[record_type] = {"error": str(exc)}
    return results
