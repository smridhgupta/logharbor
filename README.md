# 🛰️ LogHarbor

**LogHarbor** is a tactical, high-performance log analysis toolkit built for offensive and defensive cybersecurity teams. It automates deep forensic analysis of Apache access/error logs, identifies bots, scanners, and anomalies, generates risk scores for IPs, and provides beautiful CLI visualizations using `rich`.

---

## 🔥 Key Features

* 🚨 **Suspicious IP Detection** – Scores IPs using a weighted risk model (errors, known bad paths, scan UAs, method abuse).
* 🧠 **AI-ready Profiles** – Aggregates per-IP behaviors, status flips, UA switches, and session persistence.
* 📊 **Rich CLI Tables** – Beautifully rendered breakdowns using the `rich` library: status codes, methods, bots, paths, hourly heatmaps.
* 🧬 **Session Analysis** – Detects repeat visitors, user-agent switchers, and behavioral changes (e.g., 200 → 404 flips).
* 🌍 **Daily Traffic Reports** – Real/Invalid breakdowns with bot detection ratios and unique IP counts.
* 🛠️ **Auto Apache VHost Resolver** – Smart log file detection from Apache vhost config (works for hosted domains).
* 📤 **Export to JSON** – Optionally dump summarized structured findings for integration.

---

## 📦 Installation

You can either clone and run from source:

```bash
git clone https://github.com/smridhgupta/logharbor.git
cd logharbor
pip install -r requirements.txt
```

Or download precompiled binaries from the **[Releases](https://github.com/smridhgupta/logharbor/releases)** tab:

```bash
# For Debian/Ubuntu Linux only
chmod +x logharbor
chmod +x visualise
./logharbor
./visualise output.json
```

> 🔧 These are standalone builds, no Python needed. Only tested on Debian-based systems.

---

## 🚀 Usage

### 🔍 Basic CLI Usage

```bash
python logharbor.py --access /var/log/apache2/access.log --error /var/log/apache2/error.log
```

### 📁 Directory Mode

```bash
python logharbor.py --logdir /var/log/apache2
```

### 🌐 Auto-detect Logs from Apache VHost

```bash
python logharbor.py
# Will prompt for a running domain like waf.tandev.us
```

### 📤 Export to JSON

```bash
python logharbor.py --access access.log --error error.log --export-json output.json
```

---

## 📈 Offline Visualization Support

LogHarbor supports **graphical report generation** from your exported `.json` using a dedicated visualizer:

### 📊 `visualise.py` — Headless Plot Generator

Generates 6 charts from the summary:

* HTTP Status Codes
* Request Methods
* Top Requested Paths
* Top Bot IPs
* Malicious IPs by Risk Score
* Time-based Traffic Heatmap

✅ **Run with:**

```bash
python visualise.py output.json
```

All visuals will be saved under:

```
./visuals/
```

> Or use the precompiled `./visualise` binary (Debian Linux only).

---

## ⚙️ Requirements

* Python 3.7+
* `rich`
* Apache2 (for VHost detection, optional)

Install via:

```bash
pip install rich
pip install matplotlib
```

---

#### 📸 Sample Visual Outputs

### 🔢 Status Code Distribution

![status_codes](https://github.com/user-attachments/assets/ff6e5d18-7c3f-4f03-b1e5-46fa67052b13)

---

### 🌀 Request Method Breakdown

![request_methods](https://github.com/user-attachments/assets/90f7a5c2-acc7-47e8-8853-4b59819ab6b5)

---

### 🔼 Top Requested Paths

![top_paths](https://github.com/user-attachments/assets/6e65d7b9-bfe8-4c49-b661-eb170c50802f)

---

### 🤖 Top Bot IPs

![bot_ips](https://github.com/user-attachments/assets/e6e57a78-8a8b-425d-bcfb-de024a9602a1)

---

### 🚨 Malicious IPs by Risk Score

![malicious_ips](https://github.com/user-attachments/assets/c071020d-a754-4f12-99c8-a4ebe214ad61)

---

### 📈 Traffic Over Time (Hourly)

![traffic_heatmap](https://github.com/user-attachments/assets/74b32394-b904-4cf5-a140-9f63c79975d8)

---

All plots will be saved to the `./visuals/` folder as `.png` images — ideal for reports, dashboards, or forensic snapshots.


This script is headless-friendly (uses `Agg` backend) and works on servers without GUI support.

---

## 🧪 Output Highlights

* **👾 Top Bots**
* **📈 Hot Paths**
* **🚨 Top Risk IPs**
* **📆 Daily Breakdown**
* **🧬 Session Persistence**
* **🕒 Peak Traffic Hours**
* **🔥 Suspicious Requests**
* **📤 JSON Export Support**

---

## 🛡️ Ideal Use Cases

* SOC Teams and Blue Teams reviewing Apache logs
* Bug bounty and red teamers monitoring recon targets
* AI security models needing structured behavioral inputs
* Passive WAF or scanner detection

---

## 📸 Screenshots

Below are real outputs from **LogHarbor**, displaying its powerful CLI interface and rich visual reports:

### 🔍 Access Log Analysis with Top IPs and Bots

![Screenshot 2025-05-06 at 1 50 08 AM](https://github.com/user-attachments/assets/5968a8e9-6195-458b-8f1c-7ca4fe2d6580)

---

### 📊 Methods, Top Paths & Suspicious IPs

![Screenshot 2025-05-06 at 1 50 31 AM](https://github.com/user-attachments/assets/2fe71a79-74c2-4932-a75b-a5361c55302e)

---

### 🔥 Suspicious Requests and Error IPs

![Screenshot 2025-05-06 at 1 51 05 AM](https://github.com/user-attachments/assets/4e414792-b192-46fe-964c-28274cd9db7d)

---

### 🕒 Peak Traffic Hours & Risk Scores

![Screenshot 2025-05-06 at 1 51 27 AM](https://github.com/user-attachments/assets/1fa11a96-27aa-4fa9-8841-d3b39aac1466)

---

### 🧬 Session Persistence Report

![Screenshot 2025-05-06 at 1 51 41 AM](https://github.com/user-attachments/assets/967bdcf8-40d3-4297-9025-504ccb378cfe)

---

### 📆 Enhanced Daily Analytics Summary

![Screenshot 2025-05-06 at 1 51 53 AM](https://github.com/user-attachments/assets/d673a2ba-9753-4b4d-a634-fa1e61f458f5)

---

## 📜 License

GNU GPL v3 License

---

## 📣 Contributions Welcome

Got an idea for LogHarbor? Want NGINX support or CVE correlation? Open an issue or submit a PR!

