import shodan
import requests
import ipaddress
import socket
import time
from urllib.parse import urlparse
from config import SHODAN_API_KEY, TIMEOUT
from modules.common import get as http_get


def _normalize_host(target):
    raw = str(target or "").strip()
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

    return raw.lower().rstrip(".")


def _is_ip_address(value):
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _is_private_ip(target):
    try:
        ip = ipaddress.ip_address(str(target or "").strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _resolve_to_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def _format_shodan_match(entry):
    vulns = entry.get("vulns", [])
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    elif not isinstance(vulns, list):
        vulns = []

    return {
        "ip": entry.get("ip_str") or entry.get("ip"),
        "port": entry.get("port"),
        "transport": entry.get("transport"),
        "product": entry.get("product"),
        "version": entry.get("version"),
        "os": entry.get("os"),
        "banner": str(entry.get("data", ""))[:200],
        "vulns": vulns,
    }


def _host_lookup(api, ip):
    try:
        host = api.host(ip)
    except shodan.APIError as e:
        error_text = str(e)
        lowered = error_text.lower()
        hint = None
        if "401" in lowered or "invalid api key" in lowered:
            hint = "Invalid Shodan API key. Verify SHODAN_API_KEY in your .env and regenerate key if needed."
        elif "403" in lowered or "access denied" in lowered:
            hint = (
                "Shodan API access denied for host lookup. Your key may be inactive, restricted, or missing required API access."
            )
        return {"error": error_text, "method": "host", "ip": ip, "hint": hint}

    findings = [_format_shodan_match(item) for item in host.get("data", [])]
    return {
        "total": len(findings),
        "matches": findings,
        "method": "host",
        "ip": ip,
    }


def _account_limits(api):
    try:
        info = api.info()
    except shodan.APIError:
        return None

    return {
        "plan": str(info.get("plan", "unknown")),
        "query_credits": int(info.get("query_credits", 0) or 0),
        "scan_credits": int(info.get("scan_credits", 0) or 0),
        "unlocked": bool(info.get("unlocked", False)),
    }


def shodan_lookup(target):
    target = str(target or "").strip()
    if not target:
        return {"error": "No target provided for Shodan lookup"}

    # Shodan indexes public internet hosts, so private/local IP targets should be skipped.
    if _is_private_ip(target):
        return {"skipped": "Private IP target - Shodan not applicable", "target": target}

    if not SHODAN_API_KEY:
        return {"error": "No Shodan API key configured"}

    try:
        api = shodan.Shodan(SHODAN_API_KEY)

        limits = _account_limits(api)
        if limits and limits["plan"].lower() == "oss" and limits["query_credits"] <= 0 and not limits["unlocked"]:
            return {
                "error": "Shodan account lacks API lookup access on current plan",
                "hint": (
                    "Current plan is oss with zero query credits. Upgrade Shodan API access to use lookup/search "
                    "from ReconX, or skip Shodan module in scans."
                ),
                "account": limits,
                "target": target,
            }

        # Host lookups are available on lower-tier keys, while search often requires paid access.
        if _is_ip_address(target):
            return _host_lookup(api, target)

        results = api.search(f"hostname:{target}")
        findings = [_format_shodan_match(match) for match in results.get("matches", [])]
        return {
            "total": results.get("total", 0),
            "matches": findings,
            "method": "search",
            "query": f"hostname:{target}",
        }
    except shodan.APIError as e:
        error_text = str(e)
        lowered = error_text.lower()

        if "403" in lowered or "access denied" in lowered:
            resolved_ip = _resolve_to_ip(target)
            if resolved_ip:
                fallback = _host_lookup(api, resolved_ip)
                if "error" not in fallback:
                    fallback["warning"] = (
                        "Shodan search API denied (403). Returned host lookup result instead. "
                        "Search queries typically require a paid Shodan API plan."
                    )
                    fallback["resolved_from"] = target
                    return fallback

            return {
                "error": "Shodan search API denied (403 Forbidden)",
                "hint": (
                    "Your API key likely has no search permission (common with free/basic keys). "
                    "Use a paid API plan for hostname search, or provide an IP target for host lookup."
                ),
                "target": target,
            }

        return {"error": error_text}


def _build_wayback_snapshot(timestamp, original):
    ts = str(timestamp or "").strip()
    src = str(original or "").strip()
    if not ts or not src:
        return ""
    return f"https://web.archive.org/web/{ts}/{src}"


def wayback_lookup(domain, include_records=False, limit=200):
    target = str(domain or "").strip().lower()
    if not target:
        return {"urls": [], "records": []}

    # Archive.org does not index private/local network addresses.
    if _is_private_ip(target):
        return {"urls": [], "records": []}

    try:
        max_rows = max(1, int(limit))
    except (TypeError, ValueError):
        max_rows = 200

    # Build correct query patterns
    # For www.instagram.com: search "www.instagram.com" and "*.instagram.com"
    # For example.com: search "example.com" and "*.example.com"
    query_patterns = [f"{target}/*"]
    
    # If target has www prefix, also search base domain subdomains
    if target.startswith("www."):
        base_domain = target[4:]  # Remove "www." prefix
        query_patterns.append(f"*.{base_domain}/*")
    else:
        # Otherwise search all subdomains
        query_patterns.append(f"*.{target}/*")
    
    collected_urls = set()
    records_map = {}

    for pattern in query_patterns:
        for attempt in range(3):
            try:
                resp = http_get(
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": pattern,
                        "output": "json",
                        "collapse": "urlkey",
                        "limit": max_rows,
                    },
                    headers={"User-Agent": "ReconX/1.0"},
                    timeout=max(TIMEOUT, 20),
                )
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list) or len(data) <= 1:
                    break

                fields = data[0]
                if "original" not in fields:
                    break

                idx_original = fields.index("original")
                idx_timestamp = fields.index("timestamp") if "timestamp" in fields else None
                idx_status = fields.index("statuscode") if "statuscode" in fields else None
                idx_mimetype = fields.index("mimetype") if "mimetype" in fields else None

                for row in data[1:]:
                    if not isinstance(row, list) or len(row) <= idx_original:
                        continue

                    original = str(row[idx_original])
                    if not original:
                        continue
                    collected_urls.add(original)

                    if include_records and original not in records_map:
                        timestamp = str(row[idx_timestamp]) if idx_timestamp is not None and len(row) > idx_timestamp else ""
                        status = str(row[idx_status]) if idx_status is not None and len(row) > idx_status else ""
                        mimetype = str(row[idx_mimetype]) if idx_mimetype is not None and len(row) > idx_mimetype else ""
                        records_map[original] = {
                            "original": original,
                            "timestamp": timestamp,
                            "statuscode": status,
                            "mimetype": mimetype,
                            "snapshot": _build_wayback_snapshot(timestamp, original),
                        }

                break
            except (requests.RequestException, ValueError):
                if attempt < 2:
                    time.sleep(1.2 * (attempt + 1))

    urls = sorted(collected_urls)
    records = []
    if include_records:
        records = [records_map[u] for u in urls if u in records_map]

    return {"urls": urls, "records": records}


def wayback_urls(domain):
    return wayback_lookup(domain, include_records=False, limit=200)["urls"]


def run(domain, **kwargs):
    host = _normalize_host(domain)
    include_wayback_records = bool(kwargs.get("rich_wayback", False))
    wayback = wayback_lookup(host, include_records=include_wayback_records, limit=200)

    result = {
        "target_host": host,
        "shodan": shodan_lookup(host),
        "wayback_urls": wayback["urls"],
    }

    if include_wayback_records:
        result["wayback_records"] = wayback["records"]

    return result
