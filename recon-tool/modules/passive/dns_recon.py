import dns.resolver
import whois
import requests
import re
from urllib.parse import urlparse
from config import TIMEOUT


def get_dns_records(domain):
    records = {}
    record_types = ["A", "MX", "TXT", "CNAME", "NS", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records[rtype] = []

    return records


def _normalize_domain(target):
    raw = str(target or "").strip().lower()
    if not raw:
        return ""

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path

    raw = raw.split("/", 1)[0].strip()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]

    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host

    return raw.rstrip(".")


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_valid_subdomain(candidate, domain):
    sub = str(candidate or "").strip().lower().rstrip(".")
    dom = str(domain or "").strip().lower().rstrip(".")
    if not sub or not dom:
        return False
    if sub == dom:
        return False
    if not sub.endswith(f".{dom}"):
        return False
    return bool(_HOSTNAME_RE.match(sub))


def get_whois(domain):
    try:
        try:
            w = whois.whois(domain, timeout=min(TIMEOUT, 8))
        except TypeError:
            # Fallback for whois library versions that do not expose timeout kwarg.
            w = whois.whois(domain)

        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
        }
    except Exception:
        return {}


def get_subdomains_crtsh(domain, max_results=500):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for token in re.split(r"[\n,]", name):
                sub = token.strip().lower().rstrip(".")
                if sub.startswith("*."):
                    sub = sub[2:]
                if _is_valid_subdomain(sub, domain):
                    subdomains.add(sub)

        sorted_subdomains = sorted(subdomains, key=lambda s: (s.count("."), s))
        if max_results and len(sorted_subdomains) > max_results:
            return sorted_subdomains[:max_results]
        return sorted_subdomains
    except Exception:
        return []


def run(domain, **kwargs):
    clean_domain = _normalize_domain(domain)
    speed = kwargs.get("speed", "normal")
    include_whois = kwargs.get("include_whois", speed != "aggressive")
    max_subdomains = {
        "stealth": 300,
        "normal": 500,
        "aggressive": 800,
    }.get(speed, 500)

    return {
        "domain": clean_domain,
        "dns_records": get_dns_records(clean_domain),
        "whois": get_whois(clean_domain) if include_whois else {"skipped": True},
        "subdomains_crtsh": get_subdomains_crtsh(clean_domain, max_results=max_subdomains),
    }
