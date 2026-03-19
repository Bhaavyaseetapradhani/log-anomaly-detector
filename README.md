# ⚡ LLM Log Anomaly Detector

> AI-powered Windows Event Log analyzer that detects threats, maps to MITRE ATT&CK, and generates PDF incident reports — powered by Claude.

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-red?style=flat-square)
![Claude](https://img.shields.io/badge/Claude-Sonnet-green?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=flat-square)

---

## 🔍 What It Does

Paste or upload Windows Event Logs → Claude AI analyzes them → Get:

- **Plain-English threat explanations** (no log jargon)
- **Severity scoring** — Critical / High / Medium / Low
- **MITRE ATT&CK technique mapping** per finding
- **Indicators of Compromise (IOCs)** extracted automatically
- **Attack timeline reconstruction**
- **Downloadable PDF incident report**

Mirrors how enterprise tools like **Microsoft Copilot for Security** work — built to demonstrate practical AI + SOC integration.

---

## 🧠 How It Works

```
Raw Windows Event Logs
        ↓
  log_parser.py         ← extracts Event IDs, IPs, accounts, timestamps
        ↓
  Claude API (Sonnet)   ← analyzes patterns, explains threats in plain English
        ↓
  Streamlit UI          ← displays findings with severity + MITRE mapping
        ↓
  report_generator.py   ← exports professional PDF report
```

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Bhaavyaseetapradhani/log-anomaly-detector.git
cd log-anomaly-detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
streamlit run app.py
```

### 4. Enter your Anthropic API key in the sidebar
Get one free at [console.anthropic.com](https://console.anthropic.com)

---

## 🎯 Attack Scenarios (Sample Logs Built-In)

| Scenario | Event IDs Covered |
|---|---|
| Brute Force + Lateral Movement | 4625, 4624, 4672, 5140, 5145 |
| Privilege Escalation via PowerShell | 4688, 4697, 4698, 4672, 1102 |
| Credential Dumping (Mimikatz) | 4673, 4648, 4769, 4768, 4672 |
| Ransomware Pre-deployment | 4625, 4688, 4698, 7045, 1102 |

---

## 📋 Windows Event IDs Detected

| Event ID | Description | Risk |
|---|---|---|
| 4625 | Failed logon | Brute force indicator |
| 4624 | Successful logon | Baseline / lateral movement |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | Process creation | Malicious process execution |
| 4697 / 7045 | Service installed | Persistence mechanism |
| 4698 | Scheduled task created | Persistence mechanism |
| 1102 | Audit log cleared | Log tampering / cover-up |
| 4768 / 4769 | Kerberos tickets | Pass-the-ticket / Golden Ticket |
| 5140 / 5145 | Network share access | Lateral movement / data staging |

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| AI Analysis | Anthropic Claude (claude-sonnet-4) |
| Frontend | Streamlit |
| Log Parsing | Python (regex, collections) |
| PDF Reports | ReportLab |
| Threat Framework | MITRE ATT&CK |

---

## 📸 Features

- **Dark cyberpunk UI** — terminal-style aesthetic
- **4 built-in attack scenarios** for demo without real logs
- **Drag-and-drop log upload** (.txt, .log files)
- **Real-time analysis** with streaming status
- **PDF export** with full findings, IOCs, and raw log sample

---

## 🔗 Related Projects

- [SOC Automation Scripts](https://github.com/Bhaavyaseetapradhani/soc-automation-scripts)
- [Phishing Email Detection](https://github.com/Bhaavyaseetapradhani/phishing-email-detection)
- [Cybersecurity Portfolio](https://github.com/Bhaavyaseetapradhani/cybersecurity-portfolio)

---

## 👤 Author

**Bhaavya Seeta Pradhani** — SOC Analyst | AI-Driven Threat Detection  
[LinkedIn](https://linkedin.com/in/bhaavya-seeta-pradhani) · [GitHub](https://github.com/Bhaavyaseetapradhani)

---

*Built to demonstrate practical LLM + SOC integration for production security operations.*
