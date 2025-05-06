import argparse
import json
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

OUTDIR = "visuals"
os.makedirs(OUTDIR, exist_ok=True)

def save_plot(fig, name):
    fig.tight_layout()
    path = os.path.join(OUTDIR, f"{name}.png")
    fig.savefig(path)
    print(f"[✓] Saved {path}")
    plt.close(fig)

def plot_status_codes(status_codes):
    codes = list(status_codes.keys())
    counts = list(status_codes.values())
    fig, ax = plt.subplots()
    ax.bar(codes, counts, color='teal')
    ax.set_title("Status Code Distribution")
    ax.set_xlabel("HTTP Status Code")
    ax.set_ylabel("Count")
    ax.grid(True)
    save_plot(fig, "status_codes")

def plot_methods(methods):
    labels = list(methods.keys())
    sizes = list(methods.values())
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    ax.axis("equal")
    ax.set_title("Request Method Breakdown")
    save_plot(fig, "request_methods")

def plot_top_paths(top_paths):
    paths = [p[0] for p in top_paths[:10]]
    counts = [p[1] for p in top_paths[:10]]
    fig, ax = plt.subplots()
    ax.barh(paths[::-1], counts[::-1], color='purple')
    ax.set_title("Top 10 Requested Paths")
    ax.set_xlabel("Hits")
    save_plot(fig, "top_paths")

def plot_bot_ips(bot_data):
    ips = [x[0] for x in bot_data[:10]]
    counts = [x[1] for x in bot_data[:10]]
    fig, ax = plt.subplots()
    ax.barh(ips[::-1], counts[::-1], color='orange')
    ax.set_title("Top 10 Bot IPs")
    ax.set_xlabel("Scan Count")
    save_plot(fig, "bot_ips")

def plot_traffic_heatmap(heatmap):
    sorted_items = sorted(heatmap.items())
    times = [datetime.strptime(k, "%Y-%m-%d %H") for k, _ in sorted_items]
    counts = [v for _, v in sorted_items]
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(times, counts, color='navy')
    ax.set_title("Traffic Over Time")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests")
    fig.autofmt_xdate()
    save_plot(fig, "traffic_heatmap")

def plot_malicious_risk(ip_profiles):
    scored = []
    for ip, data in ip_profiles.items():
        if not data["total"]:
            continue
        score = 0
        error_rate = data["errors"] / data["total"]
        score += min(error_rate * 100, 20)
        score += min(len(data["paths"]), 20)
        score += 20 if data["scan"] else 0
        scored.append((ip, score))
    top = sorted(scored, key=lambda x: x[1], reverse=True)[:10]
    ips = [x[0] for x in top]
    scores = [x[1] for x in top]
    fig, ax = plt.subplots()
    ax.barh(ips[::-1], scores[::-1], color='red')
    ax.set_title("Top Malicious IPs by Risk Score")
    ax.set_xlabel("Score")
    save_plot(fig, "malicious_ips")

def main():
    parser = argparse.ArgumentParser(description="📊 LogHarbor Visualizer")
    parser.add_argument("json_path", help="Path to exported JSON file")
    args = parser.parse_args()

    with open(args.json_path) as f:
        data = json.load(f)

    plot_status_codes(data["status_codes"])
    plot_methods(data["methods"])
    plot_top_paths(data["top_paths"])
    plot_bot_ips(data["bots"])
    plot_traffic_heatmap(data["traffic_heatmap"])
    plot_malicious_risk(data["ip_profiles"])

    print("\n🎉 All plots saved in ./visuals/ folder")

if __name__ == "__main__":
    main()
