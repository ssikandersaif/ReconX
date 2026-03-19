import subprocess
import json
import os
import tempfile
import shutil
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
import requests
from config import WORDLISTS, FFUF_EXTENSIONS, FFUF_MATCH_CODES, FFUF_FILTER_CODES, SPEED_PROFILES
from modules.common import fetch_not_found_baseline, get as http_get, normalize_url


def _matches_baseline(entry, baseline):
    """Check if entry matches baseline using size and word count tolerance."""
    if not baseline or baseline.get("error"):
        return False

    try:
        entry_len = int(entry.get("length", 0) or 0)
        entry_words = int(entry.get("words", 0) or 0)
    except (TypeError, ValueError):
        return False

    base_len = int(baseline.get("length", 0) or 0)
    base_words = int(baseline.get("words", 0) or 0)

    # Skip if word count matches baseline exactly
    if entry_words == base_words and base_words > 0:
        return True

    # Skip if size is within 5% of baseline
    if base_len > 0:
        len_delta = abs(entry_len - base_len) / base_len
        if len_delta <= 0.05:
            return True

    # Skip if words within 10% of baseline
    if base_words > 0:
        word_delta = abs(entry_words - base_words) / base_words
        if word_delta <= 0.10:
            return True

    return False


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


def _entry_priority(entry):
    path = (urlsplit(entry.get("url", "")).path or "").lower()
    score = 0

    high_signal_tokens = (
        "admin", "login", "auth", "api", "config", "backup", "db",
        "console", "manager", "portal", "debug", ".git", ".env", "phpinfo",
    )
    for token in high_signal_tokens:
        if token in path:
            score += 3

    if any(path.endswith(ext) for ext in (".php", ".aspx", ".jsp", ".env", ".sql", ".bak", ".zip")):
        score += 2

    # Prefer cleaner paths over random fuzz garbage when clustering noisy redirects.
    if re.search(r"[a-z]{8,}\d{2,}", path):
        score -= 1

    score -= max(path.count("/") - 4, 0)
    return score


def _collapse_redirect_signature_noise(entries, max_per_signature):
    if not max_per_signature or max_per_signature <= 0:
        return entries, {"removed": 0, "signatures_collapsed": 0}

    by_signature = {}
    passthrough = []
    for entry in entries:
        status = entry.get("status")
        if status not in (301, 302):
            passthrough.append(entry)
            continue

        key = (
            status,
            int(entry.get("length", 0) or 0),
            int(entry.get("words", 0) or 0),
        )
        by_signature.setdefault(key, []).append(entry)

    reduced = list(passthrough)
    removed = 0
    signatures_collapsed = 0

    for group in by_signature.values():
        if len(group) <= max_per_signature:
            reduced.extend(group)
            continue

        signatures_collapsed += 1
        ranked = sorted(
            group,
            key=lambda item: (-_entry_priority(item), len(item.get("url", "")), item.get("url", "")),
        )
        kept = ranked[:max_per_signature]
        reduced.extend(kept)
        removed += len(group) - len(kept)

    reduced.sort(key=lambda item: item.get("url", ""))
    return reduced, {"removed": removed, "signatures_collapsed": signatures_collapsed}


def run_ffuf(url, wordlist, extra_args=None, ffuf_threads=100, ffuf_timeout=5, max_entries=None, max_time=None):
    if not shutil.which("ffuf"):
        return {"error": "ffuf not found in PATH"}
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}

    active_wordlist = wordlist
    temp_wordlist = None
    if max_entries:
        try:
            active_wordlist, temp_wordlist = _prepare_wordlist(wordlist, max_entries=max_entries)
        except (OSError, ValueError) as e:
            return {"error": f"Failed to prepare wordlist: {e}"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_file = f.name

    cmd = [
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", active_wordlist,
        "-mc", FFUF_MATCH_CODES,
        "-fc", FFUF_FILTER_CODES,
        "-o", output_file,
        "-of", "json",
        "-t", str(ffuf_threads),
        "-timeout", str(ffuf_timeout),
        "-s",
    ]

    if extra_args:
        cmd.extend(extra_args)

    if max_time:
        cmd.extend(["-maxtime", str(int(max_time))])

    try:
        process_timeout = 600
        if max_time:
            process_timeout = max(30, int(max_time) + 30)

        subprocess.run(cmd, capture_output=True, text=True, timeout=process_timeout, check=False)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        results = []
        seen_urls = set()
        base_url = normalize_url(url)
        for r in data.get("results", []):
            url_res = normalize_url(r["url"])
            path = url_res.replace(base_url, "").lstrip("/")
            
            # Filter /.ht and word count 22
            if path.startswith(".ht") or path.startswith("/.ht") or r.get("words") == 22:
                continue
                
            # Keep only useful statuses.
            if r.get("status") not in [200, 301, 302]:
                continue
                
            # Remove duplicates
            if url_res in seen_urls:
                continue
            seen_urls.add(url_res)
            
            results.append({
                "url": url_res,
                "status": r["status"],
                "length": r["length"],
                "words": r["words"],
            })
        return {"found": results, "total": len(results)}
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
        return {"error": str(e)}
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)
        if temp_wordlist and os.path.exists(temp_wordlist):
            os.unlink(temp_wordlist)


def run(url, **kwargs):
    if not url.startswith("http"):
        url = f"https://{url}"
    url = normalize_url(url)

    speed = kwargs.get("speed", "normal")
    profile = SPEED_PROFILES.get(speed, SPEED_PROFILES["normal"])
    base_threads = int(profile.get("threads", 50))
    ffuf_threads = max(10, min(200, base_threads))
    ffuf_timeout = int(profile.get("ffuf_timeout", 8 if speed == "stealth" else 5))
    worker_count = int(profile.get("content_workers", 1 if speed == "stealth" else 2))
    ffuf_max_time = profile.get("ffuf_maxtime")
    dir_wordlist_max = profile.get("dir_wordlist_max")
    file_wordlist_max = profile.get("file_wordlist_max")
    redirect_signature_cap = int(profile.get("redirect_signature_cap", 0) or 0)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        f1 = executor.submit(
            run_ffuf,
            url,
            WORDLISTS["directories"],
            None,
            ffuf_threads,
            ffuf_timeout,
            dir_wordlist_max,
            ffuf_max_time,
        )
        f2 = executor.submit(
            run_ffuf,
            url,
            WORDLISTS["files"],
            ["-e", FFUF_EXTENSIONS],
            ffuf_threads,
            ffuf_timeout,
            file_wordlist_max,
            ffuf_max_time,
        )
        dirs = f1.result()
        files = f2.result()

    baseline = fetch_not_found_baseline(url, timeout=5, verify=False)

    robots_disallowed = []
    robots_details = []
    robots_txt = ""
    try:
        resp = http_get(f"{url.rstrip('/')}/robots.txt", timeout=5, verify=False)
        if resp.status_code == 200:
            robots_txt = resp.text
            seen_robot_urls = {item.get("url") for item in dirs.get("found", [])}
            for line in resp.text.split("\n"):
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        robots_disallowed.append(path)
                        explanation = "Disallowed path may expose sensitive area names."
                        if path == "/":
                            explanation = "Entire site blocked from indexing, developer may be hiding sensitive content."
                        robots_details.append({"path": path, "explanation": explanation})

                        robots_url = normalize_url(f"{url.rstrip('/')}/{path.lstrip('/')}")
                        if robots_url not in seen_robot_urls:
                            seen_robot_urls.add(robots_url)
                            dirs.get("found", []).append({
                                "url": robots_url,
                                "status": "robots.txt",
                                "length": 0,
                                "words": 0
                            })
    except requests.RequestException:
        pass

    # Final dedupe pass after robots enrichment.
    for bucket in (dirs, files):
        if isinstance(bucket, dict) and isinstance(bucket.get("found"), list):
            unique = {}
            for entry in bucket["found"]:
                normalized = normalize_url(entry.get("url", ""))
                entry["url"] = normalized
                unique[normalized] = entry

            filtered = []
            for entry in unique.values():
                # Keep robots-derived pseudo entries untouched.
                if entry.get("status") == "robots.txt":
                    filtered.append(entry)
                    continue
                if _matches_baseline(entry, baseline):
                    continue
                filtered.append(entry)

            filtered, reduction_stats = _collapse_redirect_signature_noise(
                filtered,
                redirect_signature_cap,
            )

            bucket["found"] = filtered
            bucket["total"] = len(bucket["found"])
            if reduction_stats["removed"] > 0:
                bucket["noise_reduction"] = reduction_stats

    return {
        "directory_results": dirs,
        "file_results": files,
        "robots_disallowed": robots_disallowed,
        "robots_details": robots_details,
        "robots_txt": robots_txt,
        "baseline": baseline,
    }
