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

```bash
git clone https://github.com/smridhgupta/logharbor.git
cd logharbor
pip install -r requirements.txt
```

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

## ⚙️ Requirements

* Python 3.7+
* `rich`
* Apache2 (for VHost detection, optional)

Install via:

```bash
pip install rich
```

---

## 📜 License

GNU GPL v3 License

---

## 📣 Contributions Welcome

Got an idea for LogHarbor? Want NGINX support or CVE correlation? Open an issue or submit a PR!

