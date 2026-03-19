import subprocess
import json
import os
import tempfile
import shutil
import requests
from config import WORDLISTS, SPEED_PROFILES
from modules.common import get as http_get


def _prepare_wordlist(wordlist, max_entries=None):
    if not max_entries:
        return wordlist, None

    max_entries = int(max_entries)
    if max_entries <= 0:
        return wordlist, None

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as src, tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp:
        for idx, line in enumerate(src):
            if idx >= max_entries:
                break
            tmp.write(line)
        return tmp.name, tmp.name


def run(url, **kwargs):
    if not url.startswith("http"):
        url = f"https://{url}"
    if not shutil.which("ffuf"):
        return {"error": "ffuf not found in PATH"}

    speed = kwargs.get("speed", "normal")
    profile = SPEED_PROFILES.get(speed, SPEED_PROFILES["normal"])
    base_threads = int(profile.get("threads", 50))
    ffuf_threads = max(5, min(100, base_threads // 2))
    ffuf_timeout = 12 if speed == "stealth" else 10 if speed == "normal" else 7
    scan_timeout = int(profile.get("param_scan_timeout", 900 if speed == "stealth" else 600 if speed == "normal" else 480))
    ffuf_max_time = profile.get("param_ffuf_maxtime")
    param_wordlist_max = profile.get("param_wordlist_max")

    wordlist = WORDLISTS["parameters"]
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}

    active_wordlist = wordlist
    temp_wordlist = None
    if param_wordlist_max:
        try:
            active_wordlist, temp_wordlist = _prepare_wordlist(wordlist, max_entries=param_wordlist_max)
        except (OSError, ValueError) as e:
            return {"error": f"Failed to prepare wordlist: {e}"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_file = f.name

    # baseline request to get a reference response size to filter against
    # Use shorter timeout for baseline request to avoid hanging
    baseline_size = None
    try:
        baseline = http_get(url, timeout=5, verify=False)
        if baseline and hasattr(baseline, 'content'):
            baseline_size = len(baseline.content) if baseline.content else None
    except (requests.RequestException, requests.Timeout):
        # If baseline fails, continue without it (ffuf will match everything)
        pass

    cmd = [
        "ffuf",
        "-u", f"{url}?FUZZ=test",
        "-w", active_wordlist,
        "-mc", "200,301,302",
        "-o", output_file,
        "-of", "json",
        "-t", str(ffuf_threads),
        "-timeout", str(ffuf_timeout),
        "-s",
    ]

    if baseline_size is not None:
        cmd += ["-fs", str(baseline_size)]

    if ffuf_max_time:
        cmd += ["-maxtime", str(int(ffuf_max_time))]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=scan_timeout, check=False)
        
        # Check if output file was created and contains valid JSON
        if not os.path.exists(output_file):
            return {"error": "ffuf produced no output"}
        
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as je:
            return {"error": f"Invalid JSON from ffuf: {je}"}
        
        # Extract parameters safely
        params = []
        for r in data.get("results", []):
            try:
                if isinstance(r, dict) and "input" in r:
                    param_val = r["input"].get("FUZZ")
                    if param_val:
                        params.append(param_val)
            except (KeyError, TypeError):
                continue
        
        return {"discovered_params": params, "total": len(params)}
    except subprocess.TimeoutExpired:
        return {"error": f"ffuf scan exceeded timeout of {scan_timeout}s"}
    except OSError as e:
        return {"error": f"OS error: {e}"}
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)
        if temp_wordlist and os.path.exists(temp_wordlist):
            os.unlink(temp_wordlist)
