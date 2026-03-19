import subprocess
import nmap
import shutil
import re
from urllib.parse import urlparse
from config import SPEED_PROFILES


def parse_target(target):
    raw = (target or "").strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host_port = parsed.netloc
    else:
        host_port = raw.split("/")[0]

    host = host_port
    custom_port = None
    if ":" in host_port and not host_port.startswith("["):
        candidate_host, candidate_port = host_port.rsplit(":", 1)
        if candidate_port.isdigit():
            host = candidate_host
            custom_port = int(candidate_port)

    return host, custom_port


def rustscan(target_host, speed="normal"):
    if not shutil.which("rustscan"):
        return [], "rustscan not found in PATH"

    try:
        profile = SPEED_PROFILES.get(speed, SPEED_PROFILES["normal"])
        base_threads = int(profile.get("threads", 50))
        rustscan_batch = max(500, min(5000, base_threads * 20))
        rustscan_ulimit = max(1500, min(15000, rustscan_batch * 3))
        rustscan_timeout_ms = {
            "stealth": 2200,
            "normal": 1400,
            "aggressive": 900,
        }.get(speed, 1400)
        rustscan_timeout = 120 if speed == "stealth" else 90 if speed == "normal" else 60

        # RustScan 2.x greppable mode prints: target -> [22,80,...]
        result = subprocess.run(
            [
                "rustscan", "-a", target_host, "-g",
                "-t", str(rustscan_timeout_ms),
                "-b", str(rustscan_batch),
                "-u", str(rustscan_ulimit),
            ],
            capture_output=True, text=True, timeout=rustscan_timeout, check=False
        )

        combined_out = "\n".join([result.stdout or "", result.stderr or ""]).strip()
        ports = []

        # Format example: 10.49.190.135 -> [22,80,110]
        ports_match = re.findall(r"\[(.*?)\]", combined_out)
        if ports_match:
            port_str = ports_match[-1]
            ports = [int(p) for p in port_str.split(",") if p.strip().isdigit()]
        elif re.fullmatch(r"\s*\d+(\s*,\s*\d+)*\s*", combined_out):
            ports = [int(p.strip()) for p in combined_out.split(",")]

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "rustscan failed").strip()
            return [], err

        return sorted(set(ports)), None
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [], str(exc)


def nmap_scan(target_host, ports, speed="normal"):
    nm = nmap.PortScanner()

    normalized_ports = sorted({int(p) for p in ports if isinstance(p, int) and 0 < int(p) <= 65535})
    timing = {
        "stealth": "-T2",
        "normal": "-T4",
        "aggressive": "-T5",
    }.get(speed, "-T4")

    top_ports = {
        "stealth": 400,
        "normal": 1200,
        "aggressive": 2000,
    }.get(speed, 1200)

    try:
        if normalized_ports:
            port_str = ",".join(map(str, normalized_ports))
            nm.scan(target_host, port_str, arguments=f"-Pn -sV --open {timing}")
            mode = "targeted"
        else:
            nm.scan(target_host, arguments=f"-Pn -sV --open {timing} --top-ports {top_ports}")
            mode = "top_ports"

        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, data in nm[host][proto].items():
                    if data["state"] == "open":
                        results.append({
                            "port": port,
                            "protocol": proto,
                            "service": data.get("name"),
                            "product": data.get("product"),
                            "version": data.get("version"),
                            "extrainfo": data.get("extrainfo"),
                            "cpe": data.get("cpe"),
                        })
        return results, None, mode
    except Exception as e:
        return [], str(e), "error"


def run(target, **kwargs):
    clean_target, custom_port = parse_target(target)
    speed = kwargs.get("speed", "normal")

    rustscan_ports, rustscan_error = rustscan(clean_target, speed=speed)
    scan_ports = set(rustscan_ports)
    if custom_port:
        scan_ports.add(custom_port)

    services, nmap_error, nmap_mode = nmap_scan(clean_target, list(scan_ports), speed=speed)

    nmap_ports = {s.get("port") for s in services if isinstance(s, dict) and s.get("port")}
    combined_ports = sorted({p for p in rustscan_ports if isinstance(p, int)} | nmap_ports)

    # If RustScan found ports that Nmap service detection did not include, keep them visible in output.
    missing_from_nmap = [p for p in combined_ports if p not in nmap_ports]
    for port in missing_from_nmap:
        services.append({
            "port": port,
            "protocol": "tcp",
            "service": "unknown",
            "product": None,
            "version": None,
            "extrainfo": "Detected by RustScan only",
            "cpe": None,
        })

    open_ports = sorted({s.get("port") for s in services if isinstance(s, dict) and s.get("port")})
    if custom_port and custom_port not in open_ports:
        # Ensure explicit custom ports are represented even if service probe is limited.
        open_ports.append(custom_port)
        open_ports = sorted(open_ports)

    anon_ftp_enabled = False
    if 21 in open_ports:
        import ftplib
        try:
            ftp = ftplib.FTP(clean_target, timeout=10)
            ftp.login("anonymous", "anonymous@domain.com")
            anon_ftp_enabled = True
            ftp.quit()
        except Exception:
            pass

    return {
        "open_ports": open_ports,
        "services": services,
        "anonymous_ftp": anon_ftp_enabled,
        "scanned_host": clean_target,
        "custom_port": custom_port,
        "scanner_diagnostics": {
            "rustscan_ports": rustscan_ports,
            "rustscan_error": rustscan_error,
            "nmap_error": nmap_error,
            "nmap_mode": nmap_mode,
        },
    }
