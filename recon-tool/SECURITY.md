# Security Policy

## Supported Versions

Only the latest released version of ReconX is actively maintained and supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, report it privately by email:

- Contact: sikandersyedsaif@gmail.com

Please do not open a public GitHub issue for security bugs.

Include the following in your report:

- Clear vulnerability description
- Steps to reproduce
- Expected and actual behavior
- Impact assessment

Initial response time target: within 72 hours.

## Scope

In scope:

- Vulnerabilities in ReconX source code
- Vulnerabilities in project dependencies
- Weaknesses in scan logic that can cause materially incorrect security findings

Out of scope:

- Security issues in targets scanned by ReconX

## Responsible Disclosure Policy

When a valid report is received:

- We will acknowledge your report
- We will investigate and release a patch
- We will credit you in CHANGELOG.md if you request attribution

## Security Hardening In Current Release

ReconX includes the following controls to reduce false positives and unstable findings:

- CVE enrichment strict matching:
	- No NVD query for unversioned or Unknown components
	- CVEs older than 2010 are excluded
	- CVE descriptions must include the matched component name
- Content discovery baseline filtering by both length and word-count similarity
- Parameter fuzzing error hardening (timeout, malformed output, missing output handling)
- Wayback lookup resiliency improvements with retry/backoff and better domain pattern handling

## Report Data Handling

Scan outputs may contain sensitive infrastructure metadata.

- Treat JSON and HTML reports as confidential
- Avoid publishing raw reports to public repositories
- Redact secrets, tokens, private hostnames, and internal paths before sharing

## Legal Notice

ReconX is for authorized testing only.

The author is not responsible for misuse, unauthorized scanning, or unlawful activity performed with this tool.
