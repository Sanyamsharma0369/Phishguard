<div align="center">

# 🛡️ PhishGuard
### AI-Powered Real-Time Email Phishing Detection System

[![Java](https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://www.java.com)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)](https://tensorflow.org)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://mysql.com)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Chrome](https://img.shields.io/badge/Chrome_Extension-MV3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Sanyamsharma0369/Phishguard?style=for-the-badge&color=yellow)](https://github.com/Sanyamsharma0369/Phishguard/stargazers)

**PhishGuard** monitors your Gmail inbox in real time, scans every URL using multi-layer AI detection,
and blocks phishing threats before you click — with instant browser notifications and a live dashboard.

[🚀 Quick Start](#-quick-start) · [✨ Features](#-features) · [🧠 How It Works](#-how-it-works) · [📸 Screenshots](#-screenshots) · [🛠️ Tech Stack](#%EF%B8%8F-tech-stack)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📧 **Gmail Monitoring** | Connects via IMAP, scans new emails every 2 minutes automatically |
| 🤖 **ML Detection** | Weka RandomForest + Naive Bayes ensemble classifier |
| 🧠 **CNN Visual Analysis** | TensorFlow screenshot analysis catches visual spoofing |
| 🛡️ **Chrome Extension** | Blocks HIGH_RISK domains at the browser level in real time |
| 🔔 **Live Notifications** | WebSocket-powered toast alerts — no page refresh needed |
| 📊 **Analytics Dashboard** | 4 live charts — threats per day, top domains, risk distribution |
| 📄 **PDF Reports** | One-click downloadable dark-themed security report |
| 🗄️ **Threat Intel Cache** | Caches VirusTotal & PhishTank results to eliminate rate limits |
| ✅ **Whitelist / 🚫 Blocklist** | Manual domain management from the dashboard |
| 🚨 **Email Alerts** | Sends Gmail notification when HIGH_RISK threat is detected |

---

## 🧠 How It Works
```text
Gmail Inbox (IMAP)
       ↓
 URL Extractor
       ↓
┌─────────────────────────────────────────┐
│          Multi-Layer Analysis           │
│ ① Weka ML ② CNN ③ VirusTotal          │
│ ④ PhishTank ⑤ Keyword Analysis          │
└─────────────────────────────────────────┘
       ↓
 Decision Engine → SAFE / SUSPICIOUS / HIGH_RISK
       ↓
┌──────────────┬──────────────┬───────────────┐
│   MySQL DB   │  Dashboard   │Chrome Extension│
│  (stored)    │  (live WS)   │   (blocked)   │
└──────────────┴──────────────┴───────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Java 17+, Maven
- Python 3.11+
- MySQL 8.0
- Google Chrome

### 1. Clone
```bash
git clone https://github.com/Sanyamsharma0369/Phishguard.git
cd Phishguard
```

### 2. Configure
```bash
cp src/main/resources/config.example.properties src/main/resources/config.properties
# Edit config.properties with your Gmail + API keys
```

### 3. Database Setup
```sql
CREATE DATABASE phishguard;
-- Run the schema from /database/schema.sql
```

### 4. Python Service
```bash
cd python_service
pip install -r requirements.txt
python app.py
```

### 5. Java Backend
```bash
mvn clean package
# Or run Main.java from IntelliJ
```

### 6. Load Chrome Extension
```text
Chrome → Extensions → Developer Mode → Load Unpacked → select phishguard-extension/
```

### 7. Open Dashboard
```text
http://localhost:8080
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Core Backend** | Java 17, Spark Java, Maven |
| **Machine Learning** | Weka 3.8 — RandomForest + Naive Bayes |
| **Deep Learning** | TensorFlow 2.15, Keras (CNN) |
| **Python API** | Flask 3.0, Flask-CORS |
| **Database** | MySQL 8.0 |
| **Frontend** | HTML5, CSS3, Vanilla JS, Chart.js |
| **Browser** | Chrome Extension (Manifest V3) |
| **Real-time** | Java-WebSocket (port 8081) |
| **Email** | Jakarta Mail (IMAP/SMTP) |
| **Threat Intel** | VirusTotal API v3, PhishTank API |
| **Reports** | iTextPDF 5 |

---

## 📁 Project Structure
```text
PhishGuard/
├── src/main/java/com/phishguard/
│   ├── Main.java                        # Entry point
│   ├── email/EmailMonitor.java          # Gmail IMAP scanner
│   ├── engine/
│   │   ├── RiskScorer.java              # Decision engine
│   │   └── FeatureExtractor.java        # URL feature extraction
│   ├── ml/WekaClassifier.java           # ML model interface
│   ├── api/WebApiController.java        # REST API (Spark)
│   ├── websocket/NotificationServer.java# Live alerts
│   └── utils/
│       ├── ThreatIntelCache.java        # VT/PT caching layer
│       ├── ReportGenerator.java         # PDF generation
│       └── EmailAlerter.java            # Alert emails
├── python_service/
│   ├── app.py                           # Flask CNN API
│   ├── train_cnn.py                     # Model training
│   └── requirements.txt
├── phishguard-extension/                # Chrome MV3 Extension
│   ├── manifest.json
│   ├── background.js
│   └── popup.html
├── src/main/resources/
│   ├── dashboard.html                   # Web dashboard
│   └── config.example.properties        # Config template
└── README.md
```

---

## 🔑 API Keys Required

| Service | Get Key At | Free Tier |
|---------|-----------|-----------|
| VirusTotal | [virustotal.com](https://virustotal.com) | 500 req/day |
| PhishTank | [phishtank.com](https://phishtank.com) | Unlimited |
| Gmail App Password | [myaccount.google.com](https://myaccount.google.com/apppasswords) | Free |

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ by <a href="https://github.com/Sanyamsharma0369">Sanyam Sharma</a>
<br><br>
⭐ Star this repo if PhishGuard helped you!
</div>
