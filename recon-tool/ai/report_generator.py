import json
import re
from datetime import datetime

import requests

from config import AI_MODEL, AI_TIMEOUT, OLLAMA_URL


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 0,
}


def _normalize_severity(value):
    severity = str(value or "Info").strip().upper()
    if severity not in SEVERITY_WEIGHTS:
        return "INFO"
    return severity


def _is_target_unreachable(target, results):
    target_errors = []
    if not isinstance(results, dict):
        return True

    for module_name, module_result in results.items():
        if isinstance(module_result, dict) and module_result.get("error"):
            target_errors.append((module_name, module_result["error"]))

    has_reachable_signal = False
    web = results.get("web_fingerprint", {})
    if isinstance(web, dict) and web.get("status_code"):
        has_reachable_signal = True

    content = results.get("content_discovery", {})
    if isinstance(content, dict):
        if content.get("directory_results", {}).get("total", 0) > 0:
            has_reachable_signal = True
        if content.get("file_results", {}).get("total", 0) > 0:
            has_reachable_signal = True

    ports = results.get("port_scanner", {})
    if isinstance(ports, dict) and ports.get("open_ports"):
        has_reachable_signal = True

    if has_reachable_signal:
        return False

    if not target_errors:
        return False

    unreached_markers = [
        "name or service not known",
        "failed to resolve",
        "connection refused",
        "timed out",
        "max retries exceeded",
        "temporary failure in name resolution",
    ]

    error_blob = " | ".join(str(err).lower() for _, err in target_errors)
    return any(marker in error_blob for marker in unreached_markers)


def _calculate_score(findings, unreachable=False):
    if unreachable:
        return "N/A"
    if not findings:
        # Reachable target with no findings in current checks => provisional full score.
        return 100

    score = 100
    for finding in findings:
        severity = _normalize_severity(finding.get("severity"))
        score -= SEVERITY_WEIGHTS[severity]
    return max(0, score)


def _extract_technologies(results):
    technologies = results.get("web_fingerprint", {}).get("detected_technologies", [])
    if not isinstance(technologies, list):
        technologies = []

    final = []
    seen = set()
    for tech in technologies:
        name = str(tech.get("name", "")).strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        final.append({
            "name": name,
            "category": tech.get("category", "Technology"),
            "confidence": tech.get("confidence", "Unknown"),
            "detection_method": tech.get("detection_method", "Unknown"),
            "version": tech.get("version", ""),
        })
    # Fallback enrichment from port scanner when web fingerprint has sparse metadata.
    port_services = results.get("port_scanner", {}).get("services", [])
    for service in port_services:
        product = str(service.get("product", "") or "").strip()
        version = str(service.get("version", "") or "").strip()
        cpe = str(service.get("cpe", "") or "").strip()

        names = []
        if product:
            names.append(f"{product} {version}".strip())
        if "weblogic" in product.lower() or "weblogic" in cpe.lower():
            names.append("Oracle WebLogic Server")

        for name in names:
            key = name.lower().strip()
            if not key or key in seen:
                continue
            seen.add(key)
            final.append({
                "name": name,
                "category": "Server",
                "confidence": "Medium",
                "detection_method": "Port Scan",
                "version": version,
            })

    return final


def _technology_findings(technologies):
    findings = []
    dangerous_keywords = {
        "phpmyadmin": ("Critical", "Limit access by IP and enforce strong authentication."),
        "adminer": ("Critical", "Restrict admin tooling to internal networks only."),
        "docker api": ("Critical", "Do not expose Docker API publicly without mTLS and ACLs."),
        "jenkins": ("High", "Restrict CI admin interfaces and enforce SSO/MFA."),
        "portainer": ("Critical", "Restrict container management interfaces immediately."),
    }

    for tech in technologies:
        name = tech.get("name", "")
        lowered = name.lower()
        for keyword, (severity, remediation) in dangerous_keywords.items():
            if keyword in lowered:
                findings.append({
                    "title": f"Sensitive Technology Exposure: {name}",
                    "severity": severity,
                    "detail": "Technology can directly increase attack surface if exposed without hardening.",
                    "evidence": f"Detected by {tech.get('detection_method')}.",
                    "remediation": remediation,
                })
                break

        if lowered.startswith("php "):
            version_match = re.search(r"php\s+(\d+)\.(\d+)", lowered)
            if version_match:
                major = int(version_match.group(1))
                minor = int(version_match.group(2))
                severity = "Info"
                detail = "Supported PHP branch detected."
                if major <= 5:
                    severity = "Critical"
                    detail = "PHP 5.x is end-of-life and unsafe for internet-facing applications."
                elif major == 7 and minor <= 3:
                    severity = "High"
                    detail = "PHP 7.0-7.3 are end-of-life."
                elif major == 7 and minor == 4:
                    severity = "Medium"
                    detail = "PHP 7.4 is no longer actively supported."
                elif major == 8 and minor <= 1:
                    severity = "Low"
                    detail = "PHP 8.0-8.1 are approaching end-of-life windows."

                if severity != "Info":
                    findings.append({
                        "title": f"Outdated Runtime Detected: {name}",
                        "severity": severity,
                        "detail": detail,
                        "evidence": f"Version reported as {name}.",
                        "remediation": "Upgrade PHP to a currently supported version and apply latest security patches.",
                    })

    return findings


def _normalize_vuln_entry(entry):
    return {
        "title": entry.get("title", "Untitled Finding"),
        "severity": str(entry.get("severity", "Info")).title(),
        "detail": entry.get("detail", entry.get("description", "")),
        "evidence": entry.get("evidence", "N/A"),
        "remediation": entry.get("remediation", "Review and remediate based on system hardening best practices."),
    }


def _collapse_repeated_findings(findings):
    if not isinstance(findings, list):
        return []

    buckets = {}
    order = []
    for finding in findings:
        title = str(finding.get("title", "Untitled Finding")).strip()
        severity = str(finding.get("severity", "Info")).strip().title()
        remediation = str(finding.get("remediation", "")).strip()
        key = (title, severity, remediation)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(finding)

    merged = []
    for key in order:
        title, severity, _ = key
        items = buckets[key]
        if len(items) <= 1 or severity not in {"Info", "Low"}:
            merged.extend(items)
            continue

        base = dict(items[0])
        evidences = []
        seen_evidence = set()
        for item in items:
            evidence = str(item.get("evidence", "")).strip()
            if evidence and evidence not in seen_evidence:
                seen_evidence.add(evidence)
                evidences.append(evidence)

        sample_limit = 8
        evidence_sample = evidences[:sample_limit]
        remainder = len(evidences) - len(evidence_sample)
        if evidence_sample:
            extra = f"; ... (+{remainder} more)" if remainder > 0 else ""
            base["evidence"] = "; ".join(evidence_sample) + extra
        base["detail"] = (
            f"{base.get('detail', '').strip()} "
            f"Merged {len(items)} similar {severity.lower()} findings with title '{title}'."
        ).strip()
        merged.append(base)

    return merged


def _offline_report(target, results):
    findings = []
    technologies = _extract_technologies(results)

    headers = results.get("security_headers", {})
    for header, info in headers.get("missing_headers", {}).items():
        findings.append({
            "title": f"Missing Security Header: {header}",
            "severity": info.get("severity", "Low"),
            "detail": f"The {header} header is not set.",
            "evidence": "Header not present in response.",
            "remediation": info.get("remediation", "Set this header at web server or app layer."),
        })

    methods = results.get("http_methods", {})
    for method in methods.get("dangerous_methods", []):
        findings.append({
            "title": f"Dangerous HTTP Method Enabled: {method}",
            "severity": "High",
            "detail": f"The {method} method is accepted by the server.",
            "evidence": f"Method {method} returned success status.",
            "remediation": "Disable unnecessary HTTP methods in your server configuration.",
        })

    cookie_analysis = results.get("cookie_analysis", {})
    for cookie_name, cookie_data in cookie_analysis.get("cookies", {}).items():
        for issue in cookie_data.get("issues", []):
            findings.append({
                "title": f"Cookie Security Issue: {cookie_name} missing {issue['flag']}",
                "severity": issue.get("severity", "Medium"),
                "detail": issue.get("detail", ""),
                "evidence": cookie_name,
                "remediation": f"Set the {issue['flag']} flag on cookie {cookie_name}.",
            })

    vuln = results.get("vuln_check", {})
    for entry in vuln.get("findings", []):
        findings.append(_normalize_vuln_entry(entry))

    for cve_entry in vuln.get("cve_findings", []):
        highest_score = 0.0
        cve_ids = []
        for cve in cve_entry.get("cves", []):
            score = float(cve.get("score") or 0)
            highest_score = max(highest_score, score)
            cve_ids.append(f"{cve.get('id')} ({score})")

        if highest_score <= 0:
            continue

        severity = "Medium"
        if highest_score >= 9.0:
            severity = "Critical"
        elif highest_score >= 7.0:
            severity = "High"

        findings.append({
            "title": f"Known CVEs Found: {cve_entry.get('component', 'Unknown Component')}",
            "severity": severity,
            "detail": ", ".join(cve_ids),
            "evidence": cve_entry.get("component", "N/A"),
            "remediation": "Upgrade or patch affected component versions immediately.",
        })

    content = results.get("content_discovery", {})
    robots_paths = content.get("robots_disallowed", [])
    robots_details = content.get("robots_details", [])
    if robots_paths:
        detail_lines = []
        for item in robots_details:
            detail_lines.append(f"{item.get('path')}: {item.get('explanation')}")

        if not detail_lines:
            detail_lines = robots_paths

        findings.append({
            "title": "Sensitive Paths in robots.txt",
            "severity": "Low",
            "detail": "\n".join(detail_lines),
            "evidence": "robots.txt disallow entries found.",
            "remediation": "Do not rely on robots.txt for security. Move sensitive paths behind authentication and access controls.",
        })

    # Remove purely informational technology entries from findings; only keep risky/outdated tech cases.
    findings.extend(_technology_findings(technologies))
    findings = _collapse_repeated_findings(findings)

    unreachable = _is_target_unreachable(target, results)
    score = _calculate_score(findings, unreachable=unreachable)

    if unreachable:
        executive_summary = f"Target {target} was unreachable during scanning."
        conclusion = "No reliable attack-surface conclusions can be made until connectivity is restored."
    elif not findings:
        executive_summary = f"No actionable findings were collected for {target}."
        conclusion = "Current checks did not produce actionable findings. Score is provisional and should be validated with deeper/manual testing."
    else:
        executive_summary = f"Automated reconnaissance of {target} identified {len(findings)} findings."
        conclusion = "Prioritize remediation by severity, starting with critical and high-risk exposures."

    return {
        "executive_summary": executive_summary,
        "technical_summary": "AI analysis unavailable. Pattern-based analysis used.",
        "attack_surface": "Based on observed endpoints, exposed headers, methods, and discovered content.",
        "critical_findings": [f["title"] for f in findings if str(f.get("severity", "")).lower() == "critical"],
        "risk_priority": "Fix externally exploitable and configuration exposure findings first.",
        "conclusion": conclusion,
        "findings": findings,
        "technologies": technologies,
        "security_score": score,
        "generated_by": "offline_fallback",
        "timestamp": datetime.utcnow().isoformat(),
    }


def call_ai(prompt):
    payload = {
        "model": AI_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1200,
        },
    }

    request_timeout = min(AI_TIMEOUT, 120)
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=request_timeout)
        response.raise_for_status()
        data = response.json()
        text = data["response"]
        return text
    except requests.RequestException as exc:
        raise RuntimeError(f"AI request failed: {exc}") from exc
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"AI response parse failed: {exc}") from exc


def _strip_markdown_fences(text):
    cleaned = (text or "").strip()
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _parse_ai_json(ai_text):
    if ai_text is None or not str(ai_text).strip():
        raise ValueError("AI returned empty response")

    cleaned = _strip_markdown_fences(str(ai_text))
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("AI returned non-JSON text")

    candidate = cleaned[start:end + 1]
    return json.loads(candidate)


def _build_ai_prompt(target, findings, technologies, open_ports, unreachable):
    return f"""You are a professional penetration tester writing 
a security assessment report.

You have been given real scan data below.
You must ONLY report what is in this data.
Do not invent or assume anything.

TARGET: {target}

SCAN DATA:
{json.dumps(findings, indent=2)}

Write a professional report with these exact JSON keys:
{{
  "executive_summary": "3-4 sentences for non-technical audience. Only mention what was actually found.",
  "technical_summary": "Detailed explanation of actual findings only",
  "attack_surface": "What an attacker could realistically do with these findings",
  "critical_findings": ["list only CRITICAL severity findings"],
  "risk_priority": "Which finding to fix first and why",
  "conclusion": "Overall security posture based on actual data"
}}

RULES:
→ Return valid JSON only
→ No markdown backticks
→ No invented findings
→ No assumed vulnerabilities
→ Base everything on SCAN DATA provided
→ If scan data is empty say target was unreachable

ABSOLUTE RULES:
→ Only use data from the JSON I provide
→ Never invent findings
→ Never assume vulnerabilities
→ If a field is empty report nothing for it
→ Only write what the scan actually found
→ If target was unreachable say so clearly
→ Security score based on actual findings only
→ Empty scan = score N/A

Context Data:
Technologies: {json.dumps(technologies, indent=2)}
Open Ports: {json.dumps(open_ports, indent=2)}
Unreachable: {json.dumps(unreachable)}
"""


def generate(target, results):
    offline = _offline_report(target, results)
    offline_critical = [
        f.get("title")
        for f in offline.get("findings", [])
        if str(f.get("severity", "")).strip().lower() == "critical"
    ]

    findings_for_ai = [
        {
            "title": item.get("title"),
            "severity": item.get("severity"),
            "detail": item.get("detail"),
            "evidence": item.get("evidence"),
        }
        for item in offline.get("findings", [])
    ]
    technologies = offline.get("technologies", [])
    open_ports = results.get("port_scanner", {}).get("open_ports", [])
    unreachable = _is_target_unreachable(target, results)

    prompt = _build_ai_prompt(target, findings_for_ai, technologies, open_ports, unreachable)

    try:
        raw_ai_text = call_ai(prompt)
        parsed = _parse_ai_json(raw_ai_text)
    except Exception as exc:
        print(f"[AI] Fallback mode: {exc}")
        return offline

    report = {
        "executive_summary": parsed.get("executive_summary", offline.get("executive_summary", "")),
        "technical_summary": parsed.get("technical_summary", offline.get("technical_summary", "")),
        "attack_surface": parsed.get("attack_surface", offline.get("attack_surface", "")),
        # Keep this field deterministic based on scanned findings severity.
        "critical_findings": offline_critical,
        "risk_priority": parsed.get("risk_priority", offline.get("risk_priority", "")),
        "conclusion": parsed.get("conclusion", offline.get("conclusion", "")),
        "findings": offline.get("findings", []),
        "technologies": offline.get("technologies", []),
        "security_score": offline.get("security_score", "N/A"),
        "generated_by": "qwen",
        "timestamp": datetime.utcnow().isoformat(),
    }
    return report


class ReportGenerator:
    def __init__(self, target, results, no_ai=False):
        self.target = target
        self.results = results
        self.no_ai = no_ai

    def build(self):
        if self.no_ai:
            report = _offline_report(self.target, self.results)
            report["technical_summary"] = "AI analysis skipped via --no-ai flag."
            if report.get("security_score") == "N/A":
                report["conclusion"] = "Security score: N/A. Scan data was empty or target unreachable."
            else:
                report["conclusion"] = f"Security score: {report['security_score']}/100. Review findings and remediate by severity."
            return report
        return generate(self.target, self.results)
