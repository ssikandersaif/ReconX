import hashlib
import re
import time

import builtwith
import requests
from bs4 import BeautifulSoup

from config import DEFAULT_HEADERS, SECURITY_HEADERS, TIMEOUT
from modules.common import get as http_get, parse_cpe, request as http_request

try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except Exception:
    HAS_WAPPALYZER = False


SERVER_HEADERS = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version", "X-Runtime"]


def _normalize_service_product_name(product, vendor=None):
    raw = " ".join(part for part in [vendor, product] if part).strip()
    lowered = raw.lower()

    aliases = {
        "oracle weblogic server": "Oracle WebLogic Server",
        "oracle weblogic": "Oracle WebLogic Server",
        "weblogic server": "Oracle WebLogic Server",
        "weblogic": "Oracle WebLogic Server",
        "apache http server": "Apache Web Server",
        "nginx": "Nginx Web Server",
        "microsoft iis": "Microsoft IIS Web Server",
    }

    for key, normalized in aliases.items():
        if key in lowered:
            return normalized

    return raw.title() if raw else ""

HEADER_INFO = {
    "Strict-Transport-Security": {
        "severity": "Low",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    },
    "Content-Security-Policy": {
        "severity": "Low",
        "remediation": "Implement a strict CSP to prevent XSS and data injection attacks.",
    },
    "X-Frame-Options": {
        "severity": "Low",
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "remediation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "remediation": "Define a Permissions-Policy to restrict access to browser features.",
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "remediation": "Set 'X-XSS-Protection: 1; mode=block' for older browser support.",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "remediation": "Set 'Cross-Origin-Opener-Policy: same-origin'.",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "Low",
        "remediation": "Set 'Cross-Origin-Resource-Policy: same-origin'.",
    },
}


FAVICON_HASHES = {
    "4483d2e7fca61d72946c9cd35e5f04d7": ("WordPress CMS", "CMS"),
    "d41d8cd98f00b204e9800998ecf8427e": ("Joomla CMS", "CMS"),
}


def _add_technology(store, name, category, method, confidence="High", version=None):
    name = (name or "").strip()
    if not name:
        return
    key = name.lower()
    if key in store:
        existing = store[key]
        if not existing.get("version") and version:
            existing["version"] = version
        return

    entry = {
        "name": name,
        "category": category,
        "confidence": confidence,
        "detection_method": method,
    }
    if version:
        entry["version"] = version
    store[key] = entry


def _normalize_server_name(name):
    lowered = (name or "").strip().lower()
    if lowered == "apache":
        return "Apache Web Server"
    if lowered == "nginx":
        return "Nginx Web Server"
    if lowered == "iis":
        return "Microsoft IIS Web Server"
    if lowered == "litespeed":
        return "LiteSpeed Web Server"
    return name


def _extract_version_from_header(value):
    match = re.search(r"/(\d+(?:\.\d+){0,2})", value or "")
    return match.group(1) if match else None


def _get_authoritative_server_family(server_header):
    lowered = (server_header or "").lower()
    if "nginx" in lowered:
        return "nginx"
    if "apache" in lowered:
        return "apache"
    if "iis" in lowered:
        return "iis"
    if "litespeed" in lowered:
        return "litespeed"
    return None


def _technology_family(name):
    lowered = (name or "").lower()
    if lowered.startswith("php"):
        return "php"
    if "nginx" in lowered:
        return "nginx"
    if "apache" in lowered:
        return "apache"
    if "iis" in lowered:
        return "iis"
    if "litespeed" in lowered:
        return "litespeed"
    return lowered


def _method_rank(method):
    ranks = {
        "headers": 5,
        "builtwith": 4,
        "wappalyzer": 4,
        "port scan": 4,
        "html source": 3,
        "html meta": 3,
        "cookies": 3,
        "favicon hash": 2,
        "error page": 1,
    }
    return ranks.get((method or "").lower(), 0)


def _specificity_rank(entry):
    version = str(entry.get("version") or "")
    name = str(entry.get("name") or "")
    has_explicit_version = bool(version) or bool(re.search(r"\d+\.\d+", name))
    return (
        1 if has_explicit_version else 0,
        _method_rank(entry.get("detection_method", "")),
        len(name),
    )


def _consolidate_technologies(entries, authoritative_server=None):
    chosen = {}
    for entry in entries:
        family = _technology_family(entry.get("name", ""))
        existing = chosen.get(family)
        if not existing or _specificity_rank(entry) > _specificity_rank(existing):
            chosen[family] = entry

    if authoritative_server:
        for family, entry in list(chosen.items()):
            if entry.get("category") == "Server" and family in {"nginx", "apache", "iis", "litespeed"} and family != authoritative_server:
                chosen.pop(family, None)

    return sorted(chosen.values(), key=lambda item: item["name"].lower())


def analyze_cookie(cookie):
    issues = []
    rest = getattr(cookie, "_rest", {}) or {}
    if not cookie.has_nonstandard_attr("HttpOnly") and not rest.get("HttpOnly"):
        issues.append({"flag": "HttpOnly", "severity": "Medium", "detail": "Cookie accessible via JavaScript - XSS risk"})
    if not cookie.secure:
        issues.append({"flag": "Secure", "severity": "Medium", "detail": "Cookie transmitted over HTTP - interception risk"})
    samesite = rest.get("SameSite") or rest.get("samesite")
    if not samesite:
        issues.append({"flag": "SameSite", "severity": "Medium", "detail": "No SameSite attribute - CSRF risk"})
    elif str(samesite).lower() == "none":
        issues.append({"flag": "SameSite=None", "severity": "Low", "detail": "SameSite=None allows cross-site requests"})
    return issues


def fingerprint_headers(resp):
    findings = {}
    for header in SERVER_HEADERS:
        value = resp.headers.get(header)
        if value:
            findings[header] = value
    return findings


def fingerprint_meta(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = {}
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator:
        meta["generator"] = generator.get("content", "")
    return meta


def builtwith_lookup(url):
    try:
        return builtwith.parse(url)
    except Exception:
        return {}


def wappalyzer_lookup(url):
    if not HAS_WAPPALYZER:
        return []
    try:
        wappalyzer = Wappalyzer.latest()
        page = WebPage.new_from_url(url, verify=False)
        return list(wappalyzer.analyze(page))
    except Exception:
        return []


def merge_builtwith_technologies(detections, url):
    data = builtwith_lookup(url)
    for category, values in data.items():
        category_name = category.replace("-", " ").title()
        if not isinstance(values, list):
            continue

        for value in values:
            tech_name = str(value).strip()
            if not tech_name:
                continue

            if category.lower() == "web-servers":
                tech_name = _normalize_server_name(tech_name)
                category_name = "Server"

            _add_technology(
                detections,
                name=tech_name,
                category=category_name,
                method="builtwith",
                confidence="High",
            )


def merge_wappalyzer_technologies(detections, url):
    for tech in wappalyzer_lookup(url):
        _add_technology(
            detections,
            name=str(tech),
            category="Application",
            method="wappalyzer",
            confidence="High",
        )


def merge_manual_header_technologies(detections, response):
    headers = {k.lower(): v for k, v in response.headers.items()}

    server_header = headers.get("server", "")
    server_lower = server_header.lower()
    if "apache" in server_lower:
        _add_technology(detections, "Apache Web Server", "Server", "Headers", version=_extract_version_from_header(server_header))
    if "nginx" in server_lower:
        _add_technology(detections, "Nginx Web Server", "Server", "Headers", version=_extract_version_from_header(server_header))
    if "iis" in server_lower:
        _add_technology(detections, "Microsoft IIS Web Server", "Server", "Headers", version=_extract_version_from_header(server_header))

    powered_by = headers.get("x-powered-by", "")
    powered_by_lower = powered_by.lower()
    if "php" in powered_by_lower:
        php_version = _extract_version_from_header(powered_by)
        display_name = f"PHP {php_version}" if php_version else "PHP"
        _add_technology(detections, display_name, "Language", "Headers", version=php_version)
    if "asp.net" in powered_by_lower:
        _add_technology(detections, "ASP.NET", "Framework", "Headers")
    if "express" in powered_by_lower:
        _add_technology(detections, "Express", "Framework", "Headers")

    generator = headers.get("x-generator", "").lower()
    if "wordpress" in generator:
        _add_technology(detections, "WordPress CMS", "CMS", "Headers")
    if "joomla" in generator:
        _add_technology(detections, "Joomla CMS", "CMS", "Headers")
    if "drupal" in generator:
        _add_technology(detections, "Drupal CMS", "CMS", "Headers")

    set_cookie = headers.get("set-cookie", "").lower()
    if "phpsessid" in set_cookie:
        _add_technology(detections, "PHP", "Language", "Cookies", confidence="Medium")
    if "jsessionid" in set_cookie:
        _add_technology(detections, "Java", "Language", "Cookies", confidence="Medium")
    if "laravel_session" in set_cookie:
        _add_technology(detections, "Laravel", "Framework", "Cookies", confidence="Medium")

    if "cf-ray" in headers:
        _add_technology(detections, "Cloudflare CDN", "CDN", "Headers")
    if "x-varnish" in headers:
        _add_technology(detections, "Varnish Cache", "Caching", "Headers")


def merge_html_technologies(detections, html):
    lower_html = (html or "").lower()

    marker_map = [
        ("/wp-content/", "WordPress CMS", "CMS"),
        ("/wp-includes/", "WordPress CMS", "CMS"),
        ("/components/com_", "Joomla CMS", "CMS"),
        ("/modules/mod_", "Joomla CMS", "CMS"),
        ("/sites/default/files/", "Drupal CMS", "CMS"),
        ("drupal.settings", "Drupal CMS", "CMS"),
        ("/skin/frontend/", "Magento 1", "CMS"),
        ("/static/version", "Magento 2", "CMS"),
        ("__next_data__", "Next.js", "Framework"),
        ("__nuxt", "Nuxt.js", "Framework"),
        ("data-reactroot", "React", "Framework"),
        ("data-v-", "Vue.js", "Framework"),
        ("ng-version", "Angular", "Framework"),
        ("laravel_session", "Laravel", "Framework"),
    ]

    for marker, name, category in marker_map:
        if marker in lower_html:
            _add_technology(detections, name, category, "HTML Source", confidence="Medium")

    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator:
        generator_content = generator.get("content", "")
        content_lower = generator_content.lower()
        if "wordpress" in content_lower:
            _add_technology(detections, "WordPress CMS", "CMS", "HTML Meta", confidence="Medium", version=generator_content)
        if "joomla" in content_lower:
            _add_technology(detections, "Joomla CMS", "CMS", "HTML Meta", confidence="Medium", version=generator_content)
        if "drupal" in content_lower:
            _add_technology(detections, "Drupal CMS", "CMS", "HTML Meta", confidence="Medium", version=generator_content)


def merge_error_page_technologies(detections, url, authoritative_server=None):
    # Error page signatures are weak; only use them when stronger methods found nothing.
    if detections:
        return

    try:
        error_resp = http_get(f"{url.rstrip('/')}/thispagenotexist123", headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        error_body = error_resp.text.lower()
    except requests.RequestException:
        return

    signatures = [
        ("whoa. you're not supposed to be here", "WordPress CMS", "CMS"),
        ("the requested url was not found", "Apache Web Server", "Server"),
        ("symfony exception", "Symfony", "Framework"),
        ("laravel", "Laravel", "Framework"),
        ("django", "Django", "Framework"),
    ]
    for signature, name, category in signatures:
        if signature in error_body:
            family = _technology_family(name)
            if authoritative_server and category == "Server" and family != authoritative_server:
                continue
            _add_technology(detections, name, category, "Error Page", confidence="Low")


def merge_favicon_technologies(detections, url):
    try:
        favicon_resp = http_get(f"{url.rstrip('/')}/favicon.ico", headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
    except requests.RequestException:
        return

    if favicon_resp.status_code != 200:
        return

    favicon_hash = hashlib.md5(favicon_resp.content).hexdigest()
    if favicon_hash in FAVICON_HASHES:
        name, category = FAVICON_HASHES[favicon_hash]
        _add_technology(detections, name, category, "Favicon Hash")


def merge_port_technologies(detections, port_results):
    if not isinstance(port_results, dict):
        return

    for svc in port_results.get("services", []):
        product = str(svc.get("product", "") or "").strip()
        service_name = str(svc.get("service", "") or "").strip()
        version = str(svc.get("version", "") or "").strip() or None
        cpe = str(svc.get("cpe", "") or "").strip()

        if cpe:
            vendor, cpe_product, cpe_version = parse_cpe(cpe)
            normalized = _normalize_service_product_name(cpe_product, vendor=vendor)
            if normalized:
                _add_technology(
                    detections,
                    normalized,
                    "Server",
                    "Port Scan",
                    confidence="Medium",
                    version=cpe_version,
                )

        normalized_product = _normalize_service_product_name(product)
        if normalized_product:
            _add_technology(
                detections,
                normalized_product,
                "Server",
                "Port Scan",
                confidence="Medium",
                version=version,
            )

        if not normalized_product and service_name:
            _add_technology(
                detections,
                service_name.upper() if len(service_name) <= 4 else service_name.title(),
                "Service",
                "Port Scan",
                confidence="Low",
            )


def run(url, **kwargs):
    if not url.startswith("http"):
        url = f"https://{url}"

    retries = max(1, int(kwargs.get("web_retries", 3)))
    results = {
        "web_fingerprint": {},
        "security_headers": {},
        "http_methods": {},
        "cookie_analysis": {},
    }

    response = None
    last_exc = None

    # Retry primary request because some high-profile targets intermittently reset/throttle clients.
    for attempt in range(retries):
        try:
            response = http_get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
            break
        except requests.exceptions.SSLError as exc:
            last_exc = exc
            break
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(0.5 * (attempt + 1))

    if response is None:
        fallback_url = url.replace("https://", "http://", 1)
        for attempt in range(retries):
            try:
                response = http_get(fallback_url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
                url = fallback_url
                break
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < retries - 1:
                    time.sleep(0.5 * (attempt + 1))

    if response is None:
        return {"error": f"web_checks request failed after retries: {last_exc}"}

    detections = {}
    port_results = kwargs.get("port_results", {})
    authoritative_server = _get_authoritative_server_family(response.headers.get("Server", ""))
    merge_builtwith_technologies(detections, url)
    merge_wappalyzer_technologies(detections, url)
    merge_manual_header_technologies(detections, response)
    merge_html_technologies(detections, response.text)
    merge_port_technologies(detections, port_results)
    merge_error_page_technologies(detections, url, authoritative_server=authoritative_server)
    merge_favicon_technologies(detections, url)

    results["web_fingerprint"] = {
        "url": response.url,
        "status_code": response.status_code,
        "server_headers": fingerprint_headers(response),
        "meta_tags": fingerprint_meta(response.text),
        "detected_technologies": _consolidate_technologies(detections.values(), authoritative_server=authoritative_server),
    }

    present = {}
    missing = {}
    for header in SECURITY_HEADERS:
        value = response.headers.get(header)
        if value:
            present[header] = value
        else:
            missing[header] = HEADER_INFO.get(header, {"severity": "Low", "remediation": "Add this security header."})

    results["security_headers"] = {
        "present_headers": present,
        "missing_headers": missing,
        "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
    }

    cookies_analysis = {}
    for cookie in response.cookies:
        value = cookie.value or ""
        cookies_analysis[cookie.name] = {
            "value_preview": value[:20] + "..." if len(value) > 20 else value,
            "issues": analyze_cookie(cookie),
            "secure": bool(cookie.secure),
        }

    results["cookie_analysis"] = {
        "total_cookies": len(cookies_analysis),
        "cookies": cookies_analysis,
    }

    methods_results = {}
    try:
        options_response = http_request("OPTIONS", url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        methods_results["OPTIONS"] = {
            "status": options_response.status_code,
            "allow_header": options_response.headers.get("Allow", ""),
            "public_header": options_response.headers.get("Public", ""),
        }
    except requests.RequestException as exc:
        methods_results["OPTIONS"] = {"error": str(exc)}

    for method in ["PUT", "DELETE", "TRACE", "PATCH", "CONNECT"]:
        try:
            method_response = http_request(method, url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
            methods_results[method] = {
                "status": method_response.status_code,
                "dangerous": 200 <= method_response.status_code < 400,
            }
        except requests.RequestException as exc:
            methods_results[method] = {"error": str(exc)}

    results["http_methods"] = {
        "methods": methods_results,
        "dangerous_methods": [name for name, data in methods_results.items() if data.get("dangerous")],
    }

    return results
