import re
from urllib.parse import urlsplit, urlunsplit

import requests


SESSION = requests.Session()


def request(method, url, **kwargs):
    return SESSION.request(method, url, **kwargs)


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def normalize_url(url):
    parts = urlsplit(str(url or ""))
    clean_path = re.sub(r"/+", "/", parts.path or "/")
    if clean_path == "/.":
        clean_path = "/"
    if len(clean_path) > 1 and clean_path.endswith("/"):
        clean_path = clean_path[:-1]
    return urlunsplit((parts.scheme, parts.netloc, clean_path, "", ""))


def root_url(url):
    parts = urlsplit(str(url or ""))
    if not parts.scheme or not parts.netloc:
        return str(url or "")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def word_count(text):
    return len((text or "").split())


def fetch_not_found_baseline(url, timeout=5, verify=False, headers=None, suffix="thispathshouldnotexist123456"):
    baseline_url = f"{str(url).rstrip('/')}/{suffix}"
    try:
        resp = get(baseline_url, timeout=timeout, verify=verify, headers=headers)
        body = resp.text or ""
        return {
            "url": baseline_url,
            "status": resp.status_code,
            "length": len(body),
            "words": word_count(body),
        }
    except requests.RequestException as exc:
        return {
            "error": str(exc),
            "url": baseline_url,
            "status": None,
            "length": 0,
            "words": 0,
        }


def parse_cpe(cpe_value):
    cpe = str(cpe_value or "").strip()
    match = re.match(r"^cpe:/[aho]:([^:]+):([^:]+)(?::([^:]+))?", cpe)
    if not match:
        return None, None, None

    vendor = match.group(1).replace("_", " ").strip()
    product = match.group(2).replace("_", " ").strip()
    version = (match.group(3) or "").strip()
    if version in {"", "-", "*"}:
        version = None
    return vendor, product, version
