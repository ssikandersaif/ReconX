import requests
import re
from concurrent.futures import ThreadPoolExecutor
from config import DEFAULT_HEADERS, NVD_API_KEY, SPEED_PROFILES, TIMEOUT
from modules.common import fetch_not_found_baseline, get as http_get, parse_cpe, root_url, word_count


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT_DEFAULT = min(TIMEOUT, 6)


def _normalize_product_query(product, vendor=None, version=None):
    raw = " ".join(part for part in [vendor, product] if part).strip()
    lowered = raw.lower()

    if "weblogic" in lowered:
        base = "Oracle WebLogic Server"
    elif "apache" in lowered and "http" in lowered:
        base = "Apache HTTP Server"
    else:
        base = raw

    if not base:
        return ""
    if version:
        return f"{base} {version}".strip()
    return base


def _parse_version(text):
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    return major, minor, patch


def _add_finding(findings, title, severity, detail, remediation, evidence="N/A", seen_keys=None):
    key = (title, severity, detail, evidence)
    if seen_keys is not None:
        if key in seen_keys:
            return
        seen_keys.add(key)
    else:
        seen = {(
            f.get("title"),
            f.get("severity"),
            f.get("detail"),
            f.get("evidence", "N/A"),
        ) for f in findings}
        if key in seen:
            return

    findings.append({
        "title": title,
        "severity": severity,
        "detail": detail,
        "remediation": remediation,
        "evidence": evidence,
    })


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _collect_discovered_entries(content_results):
    by_url = {}
    for section in ("directory_results", "file_results"):
        for entry in content_results.get(section, {}).get("found", []):
            url = str(entry.get("url", "")).strip()
            if not url:
                continue

            length = _safe_int(entry.get("length"))
            words = _safe_int(entry.get("words"))
            status = _safe_int(entry.get("status"))
            metrics = None
            if length is not None and words is not None:
                metrics = {
                    "status": status,
                    "length": max(length, 0),
                    "words": max(words, 0),
                }

            existing = by_url.get(url)
            if not existing or (existing.get("metrics") is None and metrics is not None):
                by_url[url] = {"url": url, "metrics": metrics}

    return list(by_url.values())


def _fetch_response_metrics(url):
    try:
        resp = http_get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        body = resp.text or ""
        return {
            "status": resp.status_code,
            "length": len(body),
            "words": word_count(body),
        }
    except requests.RequestException:
        return None


def _is_baseline_like(metrics, baseline):
    if not metrics or not baseline:
        return False

    base_len = int(baseline.get("length", 0) or 0)
    base_words = int(baseline.get("words", 0) or 0)
    cur_len = int(metrics.get("length", 0) or 0)
    cur_words = int(metrics.get("words", 0) or 0)

    if base_len > 0:
        if abs(cur_len - base_len) / base_len <= 0.05:
            return True
    elif cur_len == base_len:
        return True

    if cur_words == base_words:
        return True

    return False


def _build_runtime_profile(speed):
    base = SPEED_PROFILES.get(speed, SPEED_PROFILES["normal"])
    max_queries = {"stealth": 4, "normal": 6, "aggressive": 8}.get(speed, 6)
    max_url_checks = {"stealth": 120, "normal": 250, "aggressive": 350}.get(speed, 250)
    workers = max(1, min(8, int(base.get("content_workers", 2)) * 2))
    nvd_timeout = min(NVD_TIMEOUT_DEFAULT, 4 if speed == "stealth" else 5 if speed == "normal" else 6)

    return {
        "max_queries": max_queries,
        "workers": workers,
        "nvd_timeout": nvd_timeout,
        "max_url_checks": max_url_checks,
        "fetch_missing_metrics": False,
    }


def query_nvd(keyword, component=None, max_results=5, timeout=NVD_TIMEOUT_DEFAULT):
    """Query NVD for CVEs. Filters out old CVEs (pre-2010) and validates component name in description."""
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        resp = http_get(NVD_URL, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            
            # Extract publish date and skip if older than 2010
            cve_id = cve.get("id", "")
            if cve_id and cve_id.startswith("CVE-"):
                year_str = cve_id.split("-")[1]
                try:
                    year = int(year_str)
                    if year < 2010:
                        continue
                except (ValueError, IndexError):
                    pass
            
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            )
            descs = cve.get("descriptions", [])
            description = next((d["value"] for d in descs if d["lang"] == "en"), "")
            
            # Validate component name appears in CVE description if component provided
            if component and component.lower() not in description.lower():
                continue
            
            cves.append({
                "id": cve.get("id"),
                "score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity"),
                "description": description[:300],
            })
        return cves
    except (requests.RequestException, ValueError):
        return []


def run(url, fingerprint_results=None, port_results=None, content_results=None, **kwargs):
    fingerprint_results = fingerprint_results or {}
    port_results = port_results or {}
    content_results = content_results or {}
    findings = []

    technologies = fingerprint_results.get("technologies", {})
    server_headers = fingerprint_results.get("server_headers", {})
    detected_tech = fingerprint_results.get("detected_technologies", [])
    services = port_results.get("services", [])

    speed = kwargs.get("speed", "normal")
    profile = _build_runtime_profile(speed)

    # Build list of (component, version, query) tuples.
    queries = set()
    for tech, versions in technologies.items():
        if isinstance(versions, list) and versions:
            version = str(versions[0]).strip()
            if version:
                queries.add((str(tech).strip(), version, f"{tech} {version}"))
        elif isinstance(versions, str):
            version = versions.strip()
            if version and re.search(r"\d", version):
                queries.add((str(tech).strip(), version, f"{tech} {version}"))

    # web_checks stores normalized output in detected_technologies.
    for tech in detected_tech:
        name = str(tech.get("name", "")).strip()
        version = str(tech.get("version", "")).strip()
        if not name or name.lower() == "unknown":
            continue
        if version:
            queries.add((name, version, f"{name} {version}"))

    for header in ["Server", "X-Powered-By"]:
        val = server_headers.get(header)
        if val:
            # Clean values for better NVD matching.
            clean_val = re.sub(r'\(.*?\)', '', val).replace('/', ' ').strip()
            tokens = clean_val.split()
            if tokens:
                component = tokens[0]
                version_match = re.search(r"(\d+(?:\.\d+){1,})", clean_val)
                if version_match:
                    queries.add((component, version_match.group(1), clean_val))
            
    # Add port scanner services (versioned only).
    for svc in services:
        prod = svc.get("product")
        ver = svc.get("version")
        cpe = svc.get("cpe")

        if prod and ver:
            normalized = _normalize_product_query(str(prod), version=str(ver))
            queries.add((str(prod).strip(), str(ver).strip(), normalized))

        vendor, cpe_product, cpe_version = parse_cpe(cpe)
        if cpe_product and cpe_version:
            normalized = _normalize_product_query(cpe_product, vendor=vendor, version=cpe_version)
            queries.add((cpe_product.strip(), cpe_version.strip(), normalized))

    # Strict query policy: only versioned, named components are eligible.
    queries = {
        (c, v, q)
        for (c, v, q) in queries
        if c and q and len(q) >= 3 and v and c.lower() != "unknown"
    }
    ranked_queries = sorted(queries, key=lambda x: len(x[2]))
    candidate_queries = ranked_queries[:profile["max_queries"]]
    valid_queries = [(c, v, q) for (c, v, q) in candidate_queries if re.search(r"\d", v)]

    def fetch_and_map(item):
        component, version, query = item
        if not version or component.lower() == "unknown":
            return None
        cves = query_nvd(query, component=component, timeout=profile["nvd_timeout"])
        return {"component": f"{component} {version}".strip(), "cves": cves} if cves else None

    with ThreadPoolExecutor(max_workers=profile["workers"]) as executor:
        results = executor.map(fetch_and_map, valid_queries)
        for res in results:
            if res:
                findings.append(res)

    extra_findings = []
    extra_finding_keys = set()
    login_hits = []
    baseline = fetch_not_found_baseline(root_url(url), timeout=TIMEOUT, verify=False, headers=DEFAULT_HEADERS)
    if isinstance(baseline, dict) and baseline.get("error"):
        baseline = None

    discovered_entries = _collect_discovered_entries(content_results)
    marker_tokens = ("phpinfo.php", "php.ini", "/config", "/database", "/docs", "login")
    prioritized = [
        entry for entry in discovered_entries
        if any(token in entry["url"].lower() for token in marker_tokens)
    ]
    if len(prioritized) < profile["max_url_checks"]:
        seen_prioritized = {item["url"] for item in prioritized}
        prioritized.extend(
            entry for entry in discovered_entries
            if entry["url"] not in seen_prioritized
        )
    discovered_entries = prioritized[:profile["max_url_checks"]]

    for entry in discovered_entries:
        original_url = entry["url"]
        lower_url = original_url.lower()
        current_metrics = entry.get("metrics")
        if current_metrics is None:
            if profile["fetch_missing_metrics"]:
                current_metrics = _fetch_response_metrics(original_url)
            else:
                continue

        if _is_baseline_like(current_metrics, baseline):
            continue

        if lower_url.endswith("/phpinfo.php"):
            _add_finding(
                extra_findings,
                "PHP Info Page Exposed",
                "Critical",
                "phpinfo.php publicly accessible, exposes full server configuration, PHP version, loaded modules, and file paths.",
                "Delete phpinfo.php immediately.",
                original_url,
                seen_keys=extra_finding_keys,
            )
        if lower_url.endswith("/php.ini"):
            _add_finding(
                extra_findings,
                "PHP Configuration File Exposed",
                "Critical",
                "php.ini publicly accessible.",
                "Remove from web root immediately.",
                original_url,
                seen_keys=extra_finding_keys,
            )
        if "/config" in lower_url:
            _add_finding(
                extra_findings,
                "Config Directory Exposed",
                "High",
                "Configuration directory appears accessible from the web.",
                "Restrict access and move sensitive files outside web root.",
                original_url,
                seen_keys=extra_finding_keys,
            )
        if "/database" in lower_url:
            _add_finding(
                extra_findings,
                "Database Directory Exposed",
                "Critical",
                "Database directory appears accessible from the web.",
                "Block access immediately and remove exposed database artifacts.",
                original_url,
                seen_keys=extra_finding_keys,
            )
        if "/docs" in lower_url:
            _add_finding(
                extra_findings,
                "Documentation Directory Exposed",
                "Medium",
                "Documentation directory is publicly accessible.",
                "Restrict access to internal documentation in production.",
                original_url,
                seen_keys=extra_finding_keys,
            )
        if "login" in lower_url:
            login_hits.append(original_url)

    if login_hits:
        unique_login_hits = sorted(set(login_hits))
        evidence_limit = 12
        evidence_samples = unique_login_hits[:evidence_limit]
        evidence = "; ".join(evidence_samples)
        remaining = len(unique_login_hits) - len(evidence_samples)
        if remaining > 0:
            evidence = f"{evidence}; ... (+{remaining} more)"

        _add_finding(
            extra_findings,
            "Login Pages Detected",
            "Info",
            (
                f"{len(unique_login_hits)} login-like endpoints were discovered. "
                "Consolidated to reduce repetitive noise in report output."
            ),
            "Enable MFA, lockout controls, and perform targeted authentication testing.",
            evidence,
            seen_keys=extra_finding_keys,
        )

    powered_by = server_headers.get("X-Powered-By", "")
    php_version = _parse_version(powered_by)
    if php_version:
        major, minor, _ = php_version
        severity = "Info"
        rationale = "Supported PHP branch detected."
        if major <= 5:
            severity = "Critical"
            rationale = "PHP 5.x is end-of-life."
        elif major == 7 and minor <= 3:
            severity = "High"
            rationale = "PHP 7.0-7.3 are end-of-life."
        elif major == 7 and minor == 4:
            severity = "Medium"
            rationale = "PHP 7.4 receives no active security support."
        elif major == 8 and minor <= 1:
            severity = "Low"
            rationale = "PHP 8.0-8.1 are approaching or at end-of-life depending on patch cadence."

        _add_finding(
            extra_findings,
            f"PHP {major}.{minor} Detected",
            severity,
            rationale,
            "Upgrade to a currently supported PHP branch and apply latest security patches.",
            powered_by,
            seen_keys=extra_finding_keys,
        )

    server_value = server_headers.get("Server", "")
    nginx_version = _parse_version(server_value if "nginx" in server_value.lower() else "")
    if nginx_version:
        n_major, n_minor, _ = nginx_version
        severity = "Info"
        detail = "Nginx version appears current."
        if (n_major, n_minor) <= (1, 18):
            severity = "High"
            detail = "Nginx 1.18 and earlier contain multiple known vulnerabilities and are outdated."
        elif (n_major, n_minor) <= (1, 20):
            severity = "Medium"
            detail = "Nginx 1.20 is aging and may miss important security updates depending on distro backports."

        _add_finding(
            extra_findings,
            f"Nginx {n_major}.{n_minor} Detected",
            severity,
            detail,
            "Update Nginx to the latest stable branch and verify vendor backports.",
            server_value,
            seen_keys=extra_finding_keys,
        )

    for tech in detected_tech:
        name = str(tech.get("name", "")).lower()
        version = str(tech.get("version", ""))
        if "php" in name and version:
            v_parsed = _parse_version(version)
            if v_parsed and v_parsed[0] <= 7:
                _add_finding(
                    extra_findings,
                    f"Outdated PHP Version in Fingerprint: {version}",
                    "High",
                    "Technology fingerprint indicates potentially outdated PHP runtime.",
                    "Verify runtime version and upgrade to a supported branch.",
                    version,
                    seen_keys=extra_finding_keys,
                )

    return {"cve_findings": findings, "findings": extra_findings}
