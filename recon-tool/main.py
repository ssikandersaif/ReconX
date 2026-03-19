#!/usr/bin/env python3
import argparse
import json
import time
import random
import importlib
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader

init(autoreset=True)

BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

PASSIVE_MODULES = ["dns_recon", "osint", "google_dorks", "github_recon"]
ACTIVE_MODULES = [
    "port_scanner", "web_checks", "content_discovery",
    "vuln_check", "param_discovery",
]

MODULE_ALIAS = {
    "dns": "dns_recon",
    "osint": "osint",
    "dorks": "google_dorks",
    "github": "github_recon",
    "ports": "port_scanner",
    "web": "web_checks",
    "content": "content_discovery",
    "vulns": "vuln_check",
    "params": "param_discovery",
}

MODULE_DEPENDENCIES = {
    "web_checks": ["port_scanner"],
    "vuln_check": ["web_checks", "port_scanner", "content_discovery"],
}

EXTERNAL_TOOL_REQUIREMENTS = {
    "content_discovery": ["ffuf"],
    "param_discovery": ["ffuf"],
    "port_scanner": ["nmap"],
}


def banner():
    tagline = (
        f"{Fore.MAGENTA}            ✦ Always Inspired,{Style.RESET_ALL}"
        f"{Fore.YELLOW} Never Alone ✦{Style.RESET_ALL}"
    )
    print(f"""{tagline}
{Fore.LIGHTMAGENTA_EX}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}  {Fore.YELLOW}Automated Penetration Testing Recon Tool{Style.RESET_ALL}
  {Fore.MAGENTA}Made by Syed Saif Sikander{Style.RESET_ALL}
  {Fore.RED}For authorized testing only.{Style.RESET_ALL}
""")


def log(msg, level="info"):
    colors = {"info": Fore.CYAN, "success": Fore.GREEN, "warn": Fore.YELLOW, "error": Fore.RED}
    prefix = {"info": "[*]", "success": "[+]", "warn": "[!]", "error": "[-]"}
    print(f"{colors.get(level, '')}{prefix.get(level, '[*]')} {msg}{Style.RESET_ALL}")


def get_target_url(target):
    if target.startswith("http"):
        return target
    # try HTTPS first, fall back to HTTP
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{target}", timeout=5, verify=False)
            return resp.url
        except requests.RequestException:
            continue
    return f"https://{target}"


def load_module(module_name, category):
    try:
        return importlib.import_module(f"modules.{category}.{module_name}")
    except ImportError as e:
        log(f"Module {module_name} failed to import: {e}", "error")
        return None


def resolve_modules(modules_arg):
    if not modules_arg:
        return PASSIVE_MODULES, ACTIVE_MODULES

    requested = [m.strip() for m in modules_arg.split(",")]
    resolved = [MODULE_ALIAS.get(m, m) for m in requested]

    passive = [m for m in resolved if m in PASSIVE_MODULES]
    active = [m for m in resolved if m in ACTIVE_MODULES]
    return passive, active


PASSIVE_SET = {"dns_recon", "osint", "google_dorks", "github_recon"}

# Modules that can legitimately take several minutes
SLOW_MODULES = {
    "port_scanner":      "Running RustScan + Nmap (can take 2-5 min)...",
    "content_discovery": "Running ffuf directory/file fuzzing (can take 3-10 min)...",
    "param_discovery":   "Running ffuf parameter fuzzing (can take 2-5 min)...",
    "google_dorks":      "Querying Google dorks with rate limiting (can take 2-4 min)...",
    "github_recon":      "Searching GitHub code (API rate limited)...",
    "osint":             "Querying Shodan + Wayback Machine...",
}


def run_module(mod, name, target, url, speed, verbose, extra_kwargs=None):
    arg = target if name in PASSIVE_SET else url
    kwargs = {"speed": speed, "verbose": verbose, **(extra_kwargs or {})}
    try:
        result = mod.run(arg, **kwargs)
        return result
    except Exception as e:
        log(f"{name} error: {e}", "error")
        return {"error": str(e)}


def stealth_delay(profile):
    delay = random.uniform(profile["delay_min"], profile["delay_max"])
    time.sleep(delay)


def run_with_status(mod, name, target, url, speed, verbose, extra_kwargs=None):
    hint = SLOW_MODULES.get(name, "")
    hint_str = f" {Fore.YELLOW}({hint}){Style.RESET_ALL}" if hint else ""
    print(f"  {Fore.CYAN}→{Style.RESET_ALL} {name}{hint_str}", flush=True)

    start = time.time()
    result = run_module(mod, name, target, url, speed, verbose, extra_kwargs)
    elapsed = time.time() - start

    status = f"{Fore.RED}[error]{Style.RESET_ALL}" if "error" in result else f"{Fore.GREEN}[done]{Style.RESET_ALL}"
    print(f"  {Fore.CYAN}→{Style.RESET_ALL} {name} {status} {Fore.CYAN}({elapsed:.1f}s){Style.RESET_ALL}", flush=True)
    return result


def warn_missing_dependencies(active_mods):
    selected = set(active_mods)
    for module_name, deps in MODULE_DEPENDENCIES.items():
        if module_name not in selected:
            continue
        missing = [dep for dep in deps if dep not in selected]
        if missing:
            log(
                f"{module_name} selected without dependencies: {', '.join(missing)}. Results may be limited.",
                "warn",
            )


def warn_missing_external_tools(active_mods):
    for module_name in active_mods:
        required_tools = EXTERNAL_TOOL_REQUIREMENTS.get(module_name, [])
        missing = [tool for tool in required_tools if not shutil.which(tool)]
        if missing:
            log(
                f"{module_name}: missing external tool(s): {', '.join(missing)}. Module may fail or run in reduced mode.",
                "warn",
            )


def build_module_kwargs(module_name, results):
    if module_name == "web_checks":
        return {"port_results": results.get("port_scanner", {})}
    if module_name == "vuln_check":
        return {
            "fingerprint_results": results.get("web_fingerprint", {}),
            "port_results": results.get("port_scanner", {}),
            "content_results": results.get("content_discovery", {}),
        }
    return {}


def execute_modules(module_names, category, target, url, speed, verbose, speed_profile, all_results, module_options=None):
    if not module_names:
        return

    phase_name = "passive reconnaissance" if category == "passive" else "active reconnaissance"
    color = Fore.CYAN if category == "passive" else Fore.YELLOW
    log(f"Starting {phase_name} ({len(module_names)} modules)...", "info")
    print()

    for i, name in enumerate(module_names, 1):
        print(f"{color}  [{i}/{len(module_names)}]{Style.RESET_ALL}", end=" ", flush=True)
        mod = load_module(name, category)
        if mod is None:
            all_results[name] = {"error": f"Failed to import modules.{category}.{name}"}
            continue

        extra_kwargs = build_module_kwargs(name, all_results) if category == "active" else None
        if category == "passive" and name == "osint" and module_options:
            if module_options.get("rich_wayback"):
                extra_kwargs = {"rich_wayback": True}
        result = run_with_status(mod, name, target, url, speed, verbose, extra_kwargs)
        if name == "web_checks" and "error" not in result:
            all_results.update(result)
        else:
            all_results[name] = result

        if speed == "stealth":
            stealth_delay(speed_profile)

    print()


def render_html_report(target, report, raw_results, output_name):
    env = Environment(loader=FileSystemLoader(str(BASE_DIR / "templates")))
    template = env.get_template("report.html")

    findings = report.get("findings", [])
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in ["Critical", "High", "Medium", "Low", "Info"]}

    html = template.render(
        target=target,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        report=report,
        raw=raw_results,
        score=report.get("security_score", 0),
        counts=counts,
    )

    html_path = REPORTS_DIR / f"{output_name}.html"
    html_path.write_text(html, encoding="utf-8")
    return html_path


def _truncate_list(items, limit):
    if not isinstance(items, list):
        return items, False
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def build_compact_results(results):
    # Keep HTML rich by rendering from full results while storing a compact JSON artifact.
    compact = json.loads(json.dumps(results, default=str))

    osint = compact.get("osint", {})
    if isinstance(osint, dict):
        wayback_urls = osint.get("wayback_urls")
        trimmed, truncated = _truncate_list(wayback_urls, 100)
        if truncated:
            osint["wayback_urls"] = trimmed
            osint["wayback_urls_truncated"] = True

        wayback_records = osint.get("wayback_records")
        trimmed_records, truncated_records = _truncate_list(wayback_records, 100)
        if truncated_records:
            osint["wayback_records"] = trimmed_records
            osint["wayback_records_truncated"] = True

    github = compact.get("github_recon", {})
    if isinstance(github, dict):
        findings = github.get("findings")
        trimmed, truncated = _truncate_list(findings, 50)
        if truncated:
            github["findings"] = trimmed
            github["findings_truncated"] = True

    dorks = compact.get("google_dorks", {}).get("dorks", {})
    if isinstance(dorks, dict):
        for query, matches in list(dorks.items()):
            trimmed, truncated = _truncate_list(matches, 25)
            if truncated:
                dorks[query] = trimmed

    content = compact.get("content_discovery", {})
    if isinstance(content, dict):
        for key in ("directory_results", "file_results"):
            section = content.get(key, {})
            if isinstance(section, dict):
                found = section.get("found")
                trimmed, truncated = _truncate_list(found, 100)
                if truncated:
                    section["found"] = trimmed
                    section["truncated"] = True
                    section["returned"] = len(trimmed)

        robots_txt = content.get("robots_txt")
        if isinstance(robots_txt, str) and len(robots_txt) > 4000:
            content["robots_txt"] = robots_txt[:4000]
            content["robots_txt_truncated"] = True

    vuln = compact.get("vuln_check", {})
    if isinstance(vuln, dict):
        cve_findings = vuln.get("cve_findings")
        if isinstance(cve_findings, list):
            for component in cve_findings:
                if isinstance(component, dict):
                    cves = component.get("cves")
                    trimmed, truncated = _truncate_list(cves, 20)
                    if truncated:
                        component["cves"] = trimmed
                        component["cves_truncated"] = True

    return compact


def save_json(data, output_name):
    json_path = REPORTS_DIR / f"{output_name}.json"
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return json_path


def build_parser():
    p = argparse.ArgumentParser(
        prog="recon-tool",
        description="Automated penetration testing reconnaissance tool",
    )
    p.add_argument("-t", "--target", required=True, help="Target domain or IP")
    p.add_argument("--modules", help="Comma-separated modules to run (e.g. dns,ports,headers)")
    p.add_argument("--no-ai", action="store_true", help="Skip AI report generation")
    p.add_argument("--speed", choices=["normal", "stealth", "aggressive"], default="normal")
    p.add_argument("--output", default=None, help="Output report filename (no extension)")
    p.add_argument("--json-only", action="store_true", help="Save JSON output only, skip HTML")
    p.add_argument("--rich-wayback", action="store_true", help="Include Wayback records metadata (timestamp, status, mimetype, snapshot link)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_ai:
        from config import OLLAMA_URL
        parsed = urlparse(OLLAMA_URL)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        try:
            requests.get(base_url, timeout=3)
        except requests.RequestException as e:
            print(f"\n[!] Ollama not reachable at {base_url}")
            print(f"    AI analysis will use fallback mode ({e})\n")

    raw_target = args.target.strip().rstrip("/")
    if raw_target.startswith(("http://", "https://")):
        parsed = urlparse(raw_target)
        target = (parsed.netloc or parsed.path).rstrip("/")
    else:
        target = raw_target
    output_name = args.output or f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    from config import SPEED_PROFILES
    speed_profile = SPEED_PROFILES.get(args.speed, SPEED_PROFILES["normal"])

    url = get_target_url(raw_target if raw_target.startswith(("http://", "https://")) else target)
    log(f"Target: {target}", "info")
    log(f"URL:    {url}", "info")
    log(f"Speed:  {args.speed}", "info")
    print()

    passive_mods, active_mods = resolve_modules(args.modules)
    warn_missing_dependencies(active_mods)
    warn_missing_external_tools(active_mods)
    all_results = {}

    module_options = {"rich_wayback": args.rich_wayback}
    execute_modules(passive_mods, "passive", target, url, args.speed, args.verbose, speed_profile, all_results, module_options)
    execute_modules(active_mods, "active", target, url, args.speed, args.verbose, speed_profile, all_results)

    # ── AI REPORT ─────────────────────────────────────────────────────────────
    log("Generating report...", "info")
    from ai.report_generator import ReportGenerator
    rg = ReportGenerator(target=target, results=all_results, no_ai=args.no_ai)
    report = rg.build()

    score = report.get("security_score", "N/A")
    if isinstance(score, (int, float)):
        color = Fore.RED if score < 40 else Fore.YELLOW if score < 70 else Fore.GREEN
        print(f"\n  Security Score: {color}{score}/100{Style.RESET_ALL}\n")
    else:
        print(f"\n  Security Score: {Fore.YELLOW}{score}{Style.RESET_ALL}\n")

    findings = report.get("findings", [])
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]

    if critical:
        log(f"{len(critical)} CRITICAL findings require immediate attention!", "error")
    if high:
        log(f"{len(high)} HIGH severity findings found.", "warn")

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    compact_results = build_compact_results(all_results)
    json_path = save_json({"target": target, "raw": compact_results, "report": report}, output_name)
    log(f"JSON saved: {json_path}", "success")

    if not args.json_only:
        html_path = render_html_report(target, report, all_results, output_name)
        log(f"HTML report: {html_path}", "success")

    print()
    log("Recon complete.", "success")


if __name__ == "__main__":
    main()
