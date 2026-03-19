import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_env_file(path):
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except OSError:
        # Keep defaults when env file cannot be read.
        return


# Prefer explicit shell env vars, then private .env.
_load_env_file(os.path.join(BASE_DIR, ".env"))

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://192.168.56.1:11434/api/generate")
AI_MODEL = os.getenv("AI_MODEL", "qwen2.5-coder:14b-instruct-q4_K_M")
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "300"))

WORDLISTS = {
    "directories": "/usr/share/wordlists/dirb/common.txt",
    "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "files": "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    "parameters": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
}

FFUF_EXTENSIONS = ".php,.html,.txt,.bak,.old,.sql,.json,.xml,.config,.env"
FFUF_MATCH_CODES = "200,301,302,403"
FFUF_FILTER_CODES = "404"

SPEED_PROFILES = {
    "normal": {
        "delay_min": 0.5,
        "delay_max": 1.5,
        "threads": 50,
        "ffuf_timeout": 5,
        "content_workers": 2,
        "redirect_signature_cap": 45,
        "param_scan_timeout": 600,
        "dork_max_queries": 14,
        "dork_num_results": 5,
        "dork_search_sleep": 2,
        "dork_delay_min": 2.5,
        "dork_delay_max": 5.5,
    },
    "stealth": {
        "delay_min": 2.0,
        "delay_max": 5.0,
        "threads": 10,
        "ffuf_timeout": 8,
        "content_workers": 1,
        "redirect_signature_cap": 80,
        "param_scan_timeout": 900,
        "dork_max_queries": 14,
        "dork_num_results": 4,
        "dork_search_sleep": 3,
        "dork_delay_min": 4.0,
        "dork_delay_max": 8.0,
    },
    "aggressive": {
        "delay_min": 0.0,
        "delay_max": 0.1,
        "threads": 160,
        "ffuf_timeout": 4,
        "ffuf_maxtime": 90,
        "content_workers": 2,
        "redirect_signature_cap": 20,
        "dir_wordlist_max": 2500,
        "file_wordlist_max": 3000,
        "param_wordlist_max": 1500,
        "param_ffuf_maxtime": 75,
        "param_scan_timeout": 180,
        "dork_max_queries": 6,
        "dork_num_results": 3,
        "dork_search_sleep": 1,
        "dork_delay_min": 0.2,
        "dork_delay_max": 0.8,
    },
}

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

TIMEOUT = 10
