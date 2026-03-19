import time
import random
from googlesearch import search
from config import SPEED_PROFILES


DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv',
    'site:{domain} filetype:sql',
    'site:{domain} ext:php inurl:id=',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:dashboard',
    'site:{domain} inurl:backup',
    'site:{domain} inurl:config',
    'site:{domain} intitle:"index of"',
    'site:{domain} "error" OR "warning" OR "exception"',
    'site:{domain} "DB_PASSWORD" OR "DB_USER" OR "API_KEY"',
    'site:{domain} "phpinfo()"',
    '"@{domain}" filetype:txt',
]


def run(domain, speed="normal", **kwargs):
    profile = SPEED_PROFILES.get(speed, SPEED_PROFILES["normal"])
    max_queries = int(profile.get("dork_max_queries", len(DORKS)))
    num_results = int(profile.get("dork_num_results", 5))
    sleep_interval = max(1, int(profile.get("dork_search_sleep", 2)))
    min_delay = float(profile.get("dork_delay_min", profile["delay_min"] + 2))
    max_delay = float(profile.get("dork_delay_max", profile["delay_max"] + 4))

    active_dorks = DORKS[:max_queries] if max_queries > 0 else DORKS
    results = {}

    for idx, dork_template in enumerate(active_dorks):
        dork = dork_template.format(domain=domain)
        try:
            hits = list(search(dork, num_results=num_results, sleep_interval=sleep_interval))
            if hits:
                results[dork] = hits
        except Exception:
            results[dork] = []

        if idx < len(active_dorks) - 1:
            time.sleep(random.uniform(min_delay, max_delay))

    return {"dorks": results}
