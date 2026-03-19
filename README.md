# ReconX

Always Inspired, Never Alone

ReconX is an automated reconnaissance toolkit for authorized penetration testing. It combines passive and active modules, then generates JSON and HTML output with optional AI summarization.

## Technologies Built With

<p align="left">
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python" />
  <img src="https://img.shields.io/badge/Ollama-black?style=for-the-badge&logo=ollama&logoColor=white" alt="Ollama" />
  <img src="https://img.shields.io/badge/Shodan-E34F26?style=for-the-badge&logo=shodan&logoColor=white" alt="Shodan" />
  <img src="https://img.shields.io/badge/GitHub%20API-%23121011.svg?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
  <img src="https://img.shields.io/badge/Jinja-white.svg?style=for-the-badge&logo=jinja&logoColor=black" alt="Jinja" />
  <img src="https://img.shields.io/badge/HTML5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5" />
  <br>
  <img src="https://img.shields.io/badge/Wappalyzer-4608AD?style=for-the-badge&logo=wappalyzer&logoColor=white" alt="Wappalyzer" />
  <img src="https://img.shields.io/badge/Wayback%20Machine-gray?style=for-the-badge" alt="Wayback Machine" />
  <img src="https://img.shields.io/badge/NVD%20CVE-red?style=for-the-badge" alt="NVD CVE" />
</p>

## What It Does

- Passive recon: DNS, WHOIS, Shodan, Wayback, Google dorks, GitHub code search
- Active recon: RustScan plus Nmap, web fingerprinting, headers/methods/cookies, ffuf content and parameter discovery
- Vulnerability enrichment: NVD CVE lookup based on detected technologies/services
- Reporting: machine-readable JSON plus HTML report
- AI mode: Ollama-based summaries with automatic offline fallback when AI is unavailable

## Runtime Behavior

- Banner prints once at startup.
- Each module shows two status lines by design: start and completion.
- AI requests use a protective timeout cap to avoid long blocking scans.
- Missing external tools are reported before active module execution.
- Offline report logic is always available; use --no-ai to force it.

## Security And Reliability Updates (2026-03-19)

- CVE matching was hardened to reduce false positives:
	- NVD lookup now runs only for versioned components.
	- Components named Unknown are skipped.
	- CVEs older than 2010 are filtered out.
	- CVEs are kept only when the component name appears in the CVE description.
- Content discovery baseline filtering was strengthened:
	- Exact baseline word-count matches are filtered.
	- Near-baseline response length (5%) is filtered.
	- Near-baseline word-count similarity (10%) is filtered.
- Parameter discovery now returns clearer errors for timeout, invalid ffuf JSON, and missing ffuf output.
- Wayback lookups now use improved domain patterns (including www/base-domain handling) and retry logic.

## Installation

### 1) System dependencies

```bash
sudo apt update
sudo apt install -y nmap ffuf seclists
```

Install RustScan manually from official releases:

https://github.com/RustScan/RustScan/releases

### 2) Python environment

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### 3) Environment variables

```bash
cp .env.example .env
```

Set values in .env (or your shell env):

- SHODAN_API_KEY
- GITHUB_TOKEN
- NVD_API_KEY
- OLLAMA_URL
- AI_MODEL
- AI_TIMEOUT

Note: OLLAMA_URL default in config.py is an example host endpoint. Update it for your environment.

Important OLLAMA_URL host/IP note:

- The Ollama host IP is not the same on every device.
- If ReconX and Ollama run on the same machine, use http://127.0.0.1:11434/api/generate
- If Ollama runs on another machine (host/VM/WSL split), use that machine's current IP.
- That IP can change when network changes (DHCP), so verify it when AI connection fails.

### 4) Ollama model setup (for AI reports)

Install/pull the model used by ReconX:

```bash
ollama pull qwen2.5-coder:14b-instruct-q4_K_M
```

Windows PowerShell (serve Ollama for remote access from your scanning machine):

```powershell
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```

After Ollama is running, verify your .env or config.py points OLLAMA_URL to that host and port (for example http://<your-ip>:11434/api/generate).

If Ollama is not available, ReconX will automatically use offline report mode. You can also force offline mode with --no-ai.

## Usage

```bash
python main.py -t example.com
```

Examples:

```bash
# full scan
python main.py -t https://example.com/

# selected modules only
python main.py -t example.com --modules dns,osint,ports,web,content,vulns,params

# stealth speed profile
python main.py -t example.com --speed stealth

# aggressive speed profile
python main.py -t example.com --speed aggressive

# force offline report generation
python main.py -t example.com --no-ai

# JSON only report
python main.py -t example.com --json-only --output client_assessment

# include rich Wayback records metadata (when available)
python main.py -t example.com --rich-wayback
```

If you run python main.py without -t/--target, argparse exits with code 2 by design.

If a scan exits with code 130, it usually means the process was manually interrupted (for example Ctrl+C), not an internal ReconX failure.

## Architecture

```text
recon-tool/
├── main.py                  # orchestration, module execution, output writing
├── config.py                # global settings, speed profiles, API/tool config
├── modules/
│   ├── common.py            # shared helpers (HTTP session, URL normalize, CPE parse, baseline)
│   ├── passive/
│   │   ├── dns_recon.py
│   │   ├── osint.py
│   │   ├── google_dorks.py
│   │   └── github_recon.py
│   └── active/
│       ├── port_scanner.py
│       ├── web_checks.py
│       ├── content_discovery.py
│       ├── vuln_check.py
│       └── param_discovery.py
├── ai/
│   └── report_generator.py  # AI + deterministic offline report builder
├── templates/
│   └── report.html
└── reports/
```

## Output

- JSON: reports/<name>.json
- HTML: reports/<name>.html

When --rich-wayback is enabled, OSINT output also includes wayback_records entries with timestamp, status code, mimetype, and direct snapshot link.

Reports may contain sensitive target data. Keep them private.

## Repository Hygiene

- Do not commit env, __pycache__, or .env.
- Keep generated reports out of source control.
- Regenerate local virtual environment as needed.

## Demo

![ReconX Report](docs/demo.png)

## Legal Disclaimer

Use only on systems you are explicitly authorized to test. Unauthorized scanning is illegal.
