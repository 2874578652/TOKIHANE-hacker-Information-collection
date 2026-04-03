import re

import requests
from bs4 import BeautifulSoup


def _guess_server(headers: dict) -> list:
    technologies = []
    for key in ("server", "x-powered-by"):
        value = headers.get(key)
        if value:
            technologies.append(f"{key}: {value}")
    return technologies


def _guess_from_html(html: str) -> list:
    technologies = []
    soup = BeautifulSoup(html, "html.parser")

    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator and generator.get("content"):
        technologies.append(f"generator: {generator['content']}")

    body = html.lower()
    patterns = {
        "wordpress": "WordPress",
        "wp-content": "WordPress",
        "shopify": "Shopify",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "react": "React",
        "vue": "Vue.js",
        "angular": "Angular",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "bootstrap": "Bootstrap",
    }
    for marker, name in patterns.items():
        if marker in body:
            technologies.append(name)

    return sorted(set(technologies))


def detect_tech_stack(url: str, timeout: int = 10) -> dict:
    headers = {"User-Agent": "ReconTool/1.0 (+https://localhost)"}
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    server_hints = _guess_server(response.headers)
    html_hints = _guess_from_html(response.text or "")
    combined = sorted(set(server_hints + html_hints))

    return {
        "url": response.url,
        "status_code": response.status_code,
        "server_headers": dict(response.headers),
        "detected_technologies": combined,
    }
