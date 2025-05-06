import re, argparse, json
from collections import Counter, defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box
import os
import sys


console = Console()

access_log_regex = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

scan_signatures = [
    "nmap", "sqlmap", "python-requests", "builtwith", "nikto", "masscan",
    "shodan", "curl", "dirbuster", "fuzz", "w3af", "havij", "wpscan", "acunetix", "arachni"
]

suspicious_methods = {"PROPFIND", "ZQLI", "SSTP_DUPLEX_POST", "TRACE", "DEBUG"}

known_bad_paths = {
    "/.git/HEAD", "/HNAP1", "/sdk", "/wp-login.php", "/phpinfo", "/config.json",
    "/admin", "/evox/about", "/.env", "/.DS_Store"
}

def parse_access_log(path):
    sessions = defaultdict(list)
    bots = Counter()
    codes = Counter()
    methods = Counter()
    paths = Counter()
    hourly_heatmap = Counter()
    per_ip_stats = defaultdict(lambda: {"total": 0, "errors": 0, "paths": set(), "ua": set(), "scan": False})
    suspicious_requests = []

    with open(path, "r") as f:
        for line in f:
            m = access_log_regex.match(line)
            if not m:
                continue

            d = m.groupdict()
            ip, ua, method, path_req = d["ip"], d["ua"].lower(), d["method"], d["path"]
            status = int(d["status"])
            time_str = d["datetime"].split()[0]
            dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S")
            hour_key = dt.strftime("%Y-%m-%d %H")

            sessions[ip].append((dt, path_req, status))
            codes[status] += 1
            methods[method] += 1
            paths[path_req] += 1
            hourly_heatmap[hour_key] += 1

            stats = per_ip_stats[ip]
            stats["total"] += 1
            stats["paths"].add(path_req)
            stats["ua"].add(ua)
            if status >= 400:
                stats["errors"] += 1

            if any(sig in ua for sig in scan_signatures):
                bots[ip] += 1
                stats["scan"] = True

            if method in suspicious_methods or path_req in known_bad_paths or status in {400, 403, 404, 405, 500, 503}:
                suspicious_requests.append((ip, method, path_req, status, ua[:60]))

    return sessions, bots, codes, methods, paths, hourly_heatmap, suspicious_requests, per_ip_stats

def parse_error_log(path):
    errors = []
    error_ips = Counter()
    with open(path, "r") as f:
        for line in f:
            if not line.strip(): continue
            errors.append(line.strip())
            ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
            if ip_match:
                error_ips[ip_match.group(1)] += 1
    return errors, error_ips

def print_table(title, data, columns, limit=10):
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    for col in columns:
        table.add_column(col, style="cyan" if col != "Count" else "magenta", justify="right" if col == "Count" else "left")
    for row in data[:limit]:
        table.add_row(*[str(x) for x in row])
    console.print(table)

def print_ip_profiles(per_ip_stats, top_n=10):
    ip_scores = sorted(per_ip_stats.items(), key=lambda x: (x[1]["errors"], x[1]["total"]), reverse=True)
    table = Table(title="🧠 Top Suspicious IPs", box=box.SIMPLE_HEAVY)
    table.add_column("IP", style="red")
    table.add_column("Req", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Error %", justify="right")
    table.add_column("Paths Hit", justify="right")
    table.add_column("Bot UA?", justify="center")

    for ip, stat in ip_scores[:top_n]:
        error_pct = f"{(stat['errors']/stat['total']*100):.1f}%" if stat['total'] else "0%"
        table.add_row(
            ip, str(stat["total"]), str(stat["errors"]),
            error_pct, str(len(stat["paths"])),
            "✔" if stat["scan"] else ""
        )
    console.print(table)

def generate_risk_scores(ip_profiles):
    scored = []
    for ip, data in ip_profiles.items():
        score = 0
        if not data["total"]:
            continue
        error_rate = data["errors"] / data["total"]
        score += min(error_rate * 100, 20)

        score += 20 if any(p in known_bad_paths for p in data["paths"]) else 0
        score += 20 if any(sig in ua for ua in data["ua"] for sig in scan_signatures) else 0
        score += min(len(data["paths"]), 20)  # unique paths
        score += 10 if data["scan"] else 0

        scored.append((ip, int(score), data))
    scored.sort(key=lambda x: x[1], reverse=True)

    table = Table(title="🚨 Top Malicious IPs by Risk Score", box=box.SIMPLE_HEAVY)
    table.add_column("IP", style="red")
    table.add_column("Risk", justify="right")
    table.add_column("Req", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Paths", justify="right")
    for ip, risk, data in scored[:10]:
        table.add_row(ip, str(risk), str(data["total"]), str(data["errors"]), str(len(data["paths"])))
    console.print(table)

def analyze_persistence(sessions):
    ip_days = defaultdict(set)
    ip_status_shift = defaultdict(list)
    ua_switchers = set()

    for ip, logs in sessions.items():
        prev_status = None
        uas = set()
        for dt, path, status in logs:
            ip_days[ip].add(dt.date())
            if prev_status and prev_status == 200 and status == 404:
                ip_status_shift[ip].append((dt, path))
            prev_status = status
        if len(set(u for _, _, s in logs for u in [s])) > 1:
            ua_switchers.add(ip)

    repeat_visitors = [ip for ip, days in ip_days.items() if len(days) > 1]
    console.rule("[bold yellow]🧬 Session Persistence Report")

    console.print(f"🌍 [bold]Repeat Visitors:[/bold] {len(repeat_visitors)}")
    for ip in repeat_visitors[:10]:
        console.print(f"  ↳ {ip} on {sorted(ip_days[ip])}")

    console.print(f"\n🔁 [bold]UA Switchers:[/bold] {len(ua_switchers)}")
    for ip in list(ua_switchers)[:10]:
        console.print(f"  ↳ {ip}")

    console.print(f"\n🔄 [bold]Status Flip (200→404):[/bold] {len(ip_status_shift)}")
    for ip, changes in list(ip_status_shift.items())[:5]:
        console.print(f"  ↳ {ip} flipped on:")
        for dt, path in changes[:3]:
            console.print(f"     [{dt}] → {path}")

def show_daily_request_breakdown(sessions, per_ip_stats):
    daily_stats = defaultdict(lambda: {
        "valid": 0,
        "invalid": 0,
        "real": 0,
        "bot": 0,
        "total": 0,
        "real_ips": set(),
        "bot_ips": set(),
    })

    for ip, logs in sessions.items():
        is_bot = per_ip_stats[ip]["scan"]
        for dt, _, status in logs:
            day = dt.strftime("%Y-%m-%d")
            stat = daily_stats[day]
            stat["total"] += 1
            if status >= 400:
                stat["invalid"] += 1
            else:
                stat["valid"] += 1
            if is_bot:
                stat["bot"] += 1
                stat["bot_ips"].add(ip)
            else:
                stat["real"] += 1
                stat["real_ips"].add(ip)

    table = Table(title="📆 Daily Request Breakdown (Valid/Invalid • Bots/Users)", box=box.SIMPLE_HEAVY)
    table.add_column("Date", style="cyan")
    table.add_column("Valid", justify="right")
    table.add_column("Invalid", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Bots", justify="right")
    table.add_column("Real", justify="right")
    table.add_column("Bot IPs", justify="right")
    table.add_column("User IPs", justify="right")
    table.add_column("Bot %", justify="right")

    for day in sorted(daily_stats):
        stat = daily_stats[day]
        total = stat["total"]
        bot_pct = f"{(stat['bot']/total*100):.1f}%" if total else "0%"
        table.add_row(
            day,
            str(stat["valid"]),
            str(stat["invalid"]),
            str(total),
            str(stat["bot"]),
            str(stat["real"]),
            str(len(stat["bot_ips"])),
            str(len(stat["real_ips"])),
            bot_pct
        )

    console.rule("[bold green]📊 Enhanced Daily Analytics Summary")
    console.print(table)

def get_enabled_vhost_logs(target_domain=None):
    from subprocess import check_output, CalledProcessError

    def normalize(path):
        return path if path.startswith("/") else f"/var/log/apache2/{os.path.basename(path)}"

    try:
        output = check_output(["apache2ctl", "-S"], universal_newlines=True)
        conf_file = None

        for line in output.splitlines():
            if target_domain in line and "(" in line and "sites-enabled" in line:
                match = re.search(r'\(([^:]+):\d+\)', line)
                if match:
                    conf_file = match.group(1)
                    break

        if conf_file and os.path.exists(conf_file):
            with open(conf_file) as f:
                content = f.read()
                access_match = re.search(r'CustomLog\s+(\S+)', content)
                error_match = re.search(r'ErrorLog\s+(\S+)', content)
                access_log = normalize(access_match.group(1)) if access_match else None
                error_log = normalize(error_match.group(1)) if error_match else None
                return access_log, error_log
    except (CalledProcessError, FileNotFoundError, IndexError) as e:
        console.print(f"[red]✖ Error parsing Apache config: {e}[/red]")
        return None, None

    return None, None


def find_existing(paths):
    return next((p for p in paths if os.path.exists(p)), None)

def main():
    parser = argparse.ArgumentParser(description="🔥 Tactical Log Analyzer")
    parser.add_argument("--access", help="Path to access log file")
    parser.add_argument("--error", help="Path to error log file")
    parser.add_argument("--logdir", help="Directory containing access/error logs")
    parser.add_argument("--export-json", help="Export structured summary to JSON")
    args = parser.parse_args()

    access_path = args.access
    error_path = args.error

    # Support for --logdir option
    if args.logdir:
        access_path = os.path.join(args.logdir, "access.log")
        error_path = os.path.join(args.logdir, "error.log")

    # If not specified, try to detect via running domain and Apache vhost
    if not access_path or not error_path:
        running_domain = input("Enter your running domain (e.g., omnirecon.tandev.us): ").strip()
        vhost_access, vhost_error = get_enabled_vhost_logs(running_domain)
        access_path = access_path or vhost_access
        error_path = error_path or vhost_error

    if not access_path or not error_path:
        console.print("[red]✖ Could not find logs for the entered domain. Please ensure the domain is configured in Apache.[/red]")
        sys.exit(1)

    if not os.path.exists(access_path) or not os.path.exists(error_path):
        console.print("[red]✖ Log files not found at resolved paths. Exiting.[/red]")
        sys.exit(1)

    console.print(f"[bold blue]→ Using access log:[/bold blue] {access_path}")
    console.print(f"[bold blue]→ Using error log:[/bold blue] {error_path}")

    # Proceed with analysis
    console.rule("[bold blue]ACCESS LOG ANALYSIS")
    sessions, bots, codes, methods, paths, heatmap, suspicious, ip_profiles = parse_access_log(access_path)

    console.print(f"[bold green]→ Total IPs:[/bold green] {len(sessions)}")
    console.print(f"[bold red]→ Bots Detected:[/bold red] {len(bots)}")
    print_table("👾 Bots", bots.most_common(), ["IP", "Count"], limit=20)
    print_table("📊 Status Codes", sorted(codes.items()), ["Code", "Count"])
    print_table("🔧 Methods", methods.most_common(), ["Method", "Count"])
    print_table("📈 Top Paths", paths.most_common(), ["Path", "Count"], limit=15)

    print_ip_profiles(ip_profiles)

    console.rule("[bold orange1]SUSPICIOUS REQUESTS")
    for ip, method, path, status, ua in suspicious[:20]:
        console.print(f"[red]{ip}[/red] → {method} {path} [{status}] - {ua}")

    console.rule("[bold orange1]ERROR LOG ANALYSIS")
    errors, error_ips = parse_error_log(error_path)
    console.print(f"[bold green]→ Total Errors:[/bold green] {len(errors)}")
    print_table("🔥 Error IPs", error_ips.most_common(), ["IP", "Count"])

    console.rule("[bold yellow]🕒 TOP TRAFFIC HOURS")
    top_hours = sorted(heatmap.items(), key=lambda x: x[1], reverse=True)[:10]
    table = Table(title="Peak Hourly Traffic", box=box.SIMPLE_HEAVY)
    table.add_column("Hour", style="cyan")
    table.add_column("Requests", style="magenta", justify="right")
    for hour, count in top_hours:
        table.add_row(hour, str(count))
    console.print(table)

    if args.export_json:
        def serialize_ip_profiles(ip_profiles):
            return {
                ip: {
                    "total": data["total"],
                    "errors": data["errors"],
                    "paths": list(data["paths"]),
                    "ua": list(data["ua"]),
                    "scan": data["scan"]
                } for ip, data in ip_profiles.items()
            }

        def serialize_sessions(sessions):
            return {
                ip: [(dt.isoformat(), path, status) for dt, path, status in logs]
                for ip, logs in sessions.items()
            }

        export = {
            "unique_ips": len(sessions),
            "bots": bots.most_common(),
            "status_codes": dict(codes),
            "methods": dict(methods),
            "top_paths": paths.most_common(),
            "suspicious_requests": suspicious,
            "error_ips": error_ips.most_common(),
            "all_error_lines": errors,
            "traffic_heatmap": dict(heatmap),
            "ip_profiles": serialize_ip_profiles(ip_profiles),
            "sessions": serialize_sessions(sessions),
        }

        with open(args.export_json, "w") as f:
            json.dump(export, f, indent=2)

        console.print(f"[green]✓ Full report exported to {args.export_json}[/green]")


    generate_risk_scores(ip_profiles)
    analyze_persistence(sessions)
    show_daily_request_breakdown(sessions, ip_profiles)

    console.rule("[bold green]✔ Analysis Done")

if __name__ == "__main__":
    main()
