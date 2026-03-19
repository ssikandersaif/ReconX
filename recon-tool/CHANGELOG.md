# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog,
and this project follows Semantic Versioning.

## [1.3.0] - 2026-03-19

### Added
- Optional rich Wayback records output via --rich-wayback (timestamp, status code, mimetype, snapshot URL).
- Scanner diagnostics metadata for port scanning results.

### Changed
- CVE enrichment now performs strict, version-aware matching to reduce unrelated NVD results.
- Content discovery baseline filtering now uses both response size and word-count similarity.
- Wayback query handling improved for www and base-domain patterns.

### Fixed
- Removed noisy CVE matches caused by generic component-only searches.
- Filtered out CVEs older than 2010 and CVEs with non-matching component descriptions.
- Improved parameter discovery robustness for ffuf timeout and malformed/missing output conditions.
- Improved Shodan behavior on unsupported plans and private IP targets.
- Improved RustScan/Nmap interoperability and fallback behavior for reliable port visibility in reports.

## [1.2.0] - 2026-03-18

### Added
- Custom port scanning support using target:port input format.
- Offline fallback report mode when AI is unavailable.

### Changed
- Increased AI timeout to 300 seconds for large scans.
- Improved technology detection accuracy across web fingerprinting and enrichment logic.
- Integrated directly with Ollama API for report generation.

### Removed
- Removed Flask proxy dependency from the AI report workflow.

## [1.1.0] - 2026-03-17

### Added
- Baseline response detection for content discovery.

### Fixed
- Reduced false positives on targets with catch-all responses.
- Improved vuln_check filtering for baseline-matching responses.

### Changed
- Improved security score calculation behavior.

## [1.0.0] - 2026-03-16

### Added
- Port scanning with RustScan and Nmap.
- DNS and WHOIS reconnaissance.
- Google dork automation.
- GitHub leak hunting.
- Web fingerprinting and technology detection.
- Security headers analysis.
- HTTP methods audit.
- Cookie security analysis.
- Content discovery with ffuf.
- Parameter discovery.
- NVD CVE vulnerability mapping.
- AI report generation using Ollama.
- Professional HTML and JSON report output.
