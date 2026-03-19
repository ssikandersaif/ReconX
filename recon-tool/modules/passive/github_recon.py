from github import Github, GithubException
from config import GITHUB_TOKEN


SECRET_QUERIES = [
    "{domain} password",
    "{domain} secret",
    "{domain} api_key",
    "{domain} token",
    "{domain} credentials",
    "{domain} db_password",
    "{domain} amazonaws",
    "{domain} BEGIN RSA PRIVATE KEY",
]


def run(domain, **kwargs):
    if not GITHUB_TOKEN:
        return {"error": "No GitHub token configured"}

    g = Github(GITHUB_TOKEN)
    findings = []
    seen = set()

    for query_template in SECRET_QUERIES:
        query = query_template.format(domain=domain)
        try:
            results = g.search_code(query)
            for idx, item in enumerate(results):
                if idx >= 5:
                    break

                key = (item.repository.full_name, item.path, item.html_url)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "query": query,
                    "repo": item.repository.full_name,
                    "file": item.path,
                    "url": item.html_url,
                })
        except GithubException as e:
            if e.status == 401:
                return {"error": "Invalid GitHub token or insufficient token permissions"}
            if e.status in (403, 422):
                # 403: rate-limited/forbidden for the query, 422: search unavailable/invalid query
                continue
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    return {"findings": findings, "total": len(findings)}
