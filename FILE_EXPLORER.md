# PhishGuard — Comprehensive File Directory & Explanation

This document provides a detailed breakdown of every file in the PhishGuard project and its specific role within the system.

---

## 1. Project Root & Configuration
| File | Responsibility |
| :--- | :--- |
| `pom.xml` | **Maven Configuration**: Defines all project dependencies (Spark, Weka, Selenium, JDBC, etc.) and build plugins. |
| `src/main/resources/config.properties` | **System Settings**: Stores sensitive credentials (DB password, Email App Passwords) and adjustable risk thresholds. |
| `PROJECT_OVERVIEW.md` | **Technical Blueprint**: High-level documentation of the architecture and data flow. |

---

## 2. Core Backend (`com.phishguard`)
### Root
- **`Main.java`**: The "Heart" of the app. It initializes the database, starts the Python CNN service, boots the Web API, and launches background monitors (Email & Clipboard).

### API Layer (`com.phishguard.api`)
- **`WebApiController.java`**: Defines all REST endpoints (`/api/scan`, `/api/incidents`, `/api/stats`). It acts as the bridge between the Frontend (Dashboard/Extension) and the Backend Engine.

### Database Layer (`com.phishguard.database`)
- **`DBConnection.java`**: A Singleton class ensuring only one connection pool to MySQL is active.
- **`IncidentDAO.java`**: Handles saving and retrieving incident records (URLs, scores, decisions).
- **`LogDAO.java`**: Records system events (Errors, Info, Critical alerts) into the database for auditing.
- **`QuarantineDAO.java`**: Manages the auto-blocking of domains that have been confirmed as malicious.

### Detection Layers (`com.phishguard.detection`)
- **`AIModelEngine.java`**: Uses Weka to load pre-trained Random Forest and Naive Bayes models to classify URL structures.
- **`URLFeatureExtractor.java`**: Converts a raw URL string into a numeric vector (8 features like length, dot count, entropy) for the AI models.
- **`ThreatIntelChecker.java`**: Connects to the **VirusTotal** and **PhishTank** APIs to check if a URL is already globally blacklisted.
- **`VisualAnalyzer.java`**: Takes a screenshot of the target URL and sends it to the Flask microservice for brand impersonation analysis.
- **`SenderAnalyzer.java`**: Analyzes the email sender's address for domain spoofing (e.g., `paypa1.com` vs `paypal.com`).
- **`TextNLPAnalyzer.java`**: Scans the email body for high-pressure keywords (e.g., "urgent", "verify account", "unauthorized login").

### Email Intelligence (`com.phishguard.email`)
- **`EmailMonitor.java`**: A background thread that logs into your Gmail/Outlook (via IMAP) every 60 seconds to scan new emails.
- **`EmailParser.java`**: Converts complex MIME email objects into a simple Java object containing the sender, subject, and body.
- **`URLExtractor.java`**: Uses Regular Expressions (Regex) to pull all links out of a raw email body.

### The Engine (`com.phishguard.engine`)
- **`RiskScorer.java`**: The central data object. It follows a URL from the moment it is detected until it has a final score, holding all the evidence gathered along the way.
- **`DecisionEngine.java`**: Applies final logic. It decides if a 0.72 score counts as `HIGH_RISK` or `SUSPICIOUS` and triggers the Auto-Blocker.
- **`ExplainabilityEngine.java`**: The "XAI" component. It breaks down the math into "Red Flags" and "Green Flags" so humans can understand why a URL was blocked.
- **`MitigationEngine.java`**: Executes the response (Quarantining the domain, sending alerts, or logging the event).

---

## 3. Graphical Interfaces (`com.phishguard.gui` & Web)
### Java Desktop App (Swing)
- **`SplashScreen.java`**: Shows a premium animated logo while the system loads.
- **`MainWindow.java`**: The frame containing all sidebar navigation.
- **`DashboardPanel.java`**: Shows live stats and "Threat Level" gauges.
- **`ScannerPanel.java`**: A manual search bar where you can paste a URL to test it instantly.
- **`LogViewerPanel.java`**: A detailed table view of every incident stored in the database.
- **`SettingsPanel.java`**: Allows you to adjust AI sensitivity and update API keys without touching the code.

### Web Dashboard
- **`src/main/resources/dashboard.html`**: A modern, dark-themed HTML/JS dashboard that provides a real-time "SOC" (Security Operations Center) view.

---

## 4. Utilities & Helpers (`com.phishguard.utils`)
- **`Constants.java`**: The single source of truth for all "Magic Numbers" (weights, thresholds, table names).
- **`WhoisChecker.java`**: Performs real-time WHOIS lookups to see if a domain was created very recently (a common sign of phishing).
- **`EntropyCalculator.java`**: Measures the "randomness" of a URL to detect if it's been obfuscated or encoded.
- **`ConfigLoader.java`**: Safely loads settings from the `config.properties` file.
- **`PDFReportGenerator.java`**: Uses the iText library to generate professional PDF summaries for any threat found.
- **`WekaTrainer.java`**: A developer tool used to retrain the ML models when you have new phishing datasets.

---

## 5. Networking & Services
- **`com.phishguard.websocket.NotificationServer.java`**: Runs a WebSocket server that "pushes" alerts to the dashboard the exact millisecond a threat is detected.
- **`python_service/app.py`**: The Python Flask app that runs the Deep Learning CNN for visual analysis.
