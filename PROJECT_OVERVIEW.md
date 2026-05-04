# PhishGuard - AI Phishing Defense Technical Documentation

## 1. Project Overview
**PhishGuard** is an advanced, multi-layered phishing detection and mitigation system designed to protect users from malicious URLs across various vectors (Emails, Clipboard, and Manual Input). 

- **Problem Solved**: Modern phishing attacks bypass traditional blacklists by using zero-day domains and visual impersonation. PhishGuard addresses this by combining Machine Learning (ML), Natural Language Processing (NLP), and Computer Vision (CNN).
- **Core Functionality**:
    - **Real-time Monitoring**: Automatically scans incoming emails (IMAP) and system clipboard.
    - **AI Detection**: Uses Weka-based ML models to analyze URL structures.
    - **Visual Analysis**: Uses a Deep Learning CNN (Python/Flask) to detect brand impersonation via screenshots.
    - **Live Dashboard**: A modern web interface for real-time monitoring and incident response.

---

## 2. Architecture
The project follows a **Hybrid Monolithic Architecture** with a specialized microservice for heavy AI computations.

### Component Breakdown
- **Java Core (The Engine)**: Handles orchestration, database management, email polling, and primary scoring logic.
- **Python Service (Visual CNN)**: A Flask-based microservice that runs a TensorFlow/Keras model to analyze webpage screenshots.
- **Web Dashboard**: A frontend built with HTML/JavaScript that communicates with the Java backend via a REST API and WebSockets.
- **MySQL Database**: Stores incident history, whitelist/blacklist data, and configuration logs.

### Data Flow
1. **Source**: A URL is detected in an email or copied to the clipboard.
2. **Analysis Pipeline**: The URL is passed through 5 analysis layers:
    - **Layer 1 (ML)**: URL structure features (length, entropy, subdomains).
    - **Layer 2 (NLP)**: Email text analysis for urgency or credential-related keywords.
    - **Layer 3 (Threat Intel)**: Real-time queries to VirusTotal and PhishTank.
    - **Layer 4 (Visual)**: Screenshot analysis via the Flask CNN microservice.
    - **Layer 5 (WHOIS)**: Domain age calculation (flagging domains < 30 days old).
3. **Decision**: The `DecisionEngine` computes a weighted score and classifies the URL as `SAFE`, `SUSPICIOUS`, or `HIGH_RISK`.
4. **Action**: `MitigationEngine` triggers alerts, emails the user, or blocks access.
5. **Reporting**: Results are stored in MySQL and pushed to the dashboard via WebSockets.

---

## 3. Workflow & Execution Flow
### Entry Point: `Main.java`
The application starts in `Main.java`, which performs the following initialization:
1. **Flask CNN Service**: Checks if the Python service is running; starts it if not.
2. **Database Connection**: Initializes the MySQL pool via `DBConnection`.
3. **ML Models**: Loads the Weka NaiveBayes and RandomForest models into memory.
4. **WebSocket Server**: Starts the `NotificationServer` on port `8081` for live dashboard updates.
5. **REST API**: Starts the Spark-based `WebApiController` on port `8080`.
6. **Background Monitors**: Launches the `EmailMonitor` (polling thread) and `ClipboardMonitor`.

### Request/Response Lifecycle (Scan Request)
1. **Client** (Browser/Extension) sends a POST request to `/api/scan`.
2. **WebApiController** receives the URL and creates a `RiskScorer` object.
3. **RiskScorer.score()** runs the 5-layer pipeline.
4. **DecisionEngine** returns the final classification.
5. **JSON Response** is sent back to the client with the score and breakdown.

---

## 4. File & Folder Structure
| Directory / File | Responsibility |
| :--- | :--- |
| `com.phishguard.api` | Spark Java controllers for REST endpoints and dashboard routes. |
| `com.phishguard.database` | MySQL interaction (JDBC), DAOs for Incidents, Logs, and Whitelist. |
| `com.phishguard.detection` | Core analysis logic (AIModelEngine, ThreatIntel, VisualAnalyzer). |
| `com.phishguard.engine` | Orchestration logic (RiskScorer, DecisionEngine, MitigationEngine). |
| `com.phishguard.monitor` | Background listeners for Email (IMAP) and Clipboard events. |
| `com.phishguard.utils` | Helpers for WHOIS, Config loading, PDF generation, and Entropy. |
| `src/main/resources` | Configuration, ML models, and the Dashboard HTML. |
| `python_service/` | Python Flask app and TensorFlow models for visual analysis. |

---

## 5. Dependencies & Libraries
- **Spark Java**: Lightweight web framework for the API.
- **Weka**: Machine Learning library for URL feature classification.
- **Selenium**: Automates headless Chrome for capturing webpage screenshots.
- **Jakarta Mail**: IMAP/SMTP protocol handling for email monitoring.
- **Java-WebSocket**: Real-time push notifications.
- **MySQL Connector**: JDBC driver for database storage.
- **iText**: Library for generating PDF incident reports.

---

## 6. Data Handling
- **Database Schema**:
    - `incidents`: Stores every URL scanned, its score, decision, and metadata.
    - `processed_emails`: Deduplication table to ensure emails aren't scanned twice.
    - `whitelist`: Domains manually marked as safe by the administrator.
    - `manual_blocks`: Domains manually blocked by the administrator.
- **External Integrations**:
    - **VirusTotal API**: Checks URLs against 70+ antivirus engines.
    - **PhishTank API**: Checks URLs against a community-driven phishing database.

---

## 7. How It Works (End-to-End Example)
1. **User Action**: A user receives a phishing email containing `http://paypal-secure-login.xyz`.
2. **Detection**: `EmailMonitor` picks up the email within 60 seconds.
3. **Processing**:
    - The ML model sees `.xyz` and a long URL (High Score).
    - The WHOIS check sees the domain was registered 2 days ago (High Score).
    - The CNN service sees the page looks exactly like PayPal (High Score).
4. **Output**: The `DecisionEngine` calculates a final score of **0.92 (HIGH_RISK)**.
5. **Mitigation**:
    - The incident is saved to the database.
    - A red alert pops up on the Live Dashboard via WebSockets.
    - An alert email is sent to the admin.
    - The URL is added to the local blocklist.

---

## 8. Improvement Suggestions
- **Performance**: Move Selenium (Screenshot capture) to an asynchronous worker queue (like RabbitMQ) to prevent blocking the main pipeline.
- **Scalability**: Migrate the Java monolith into microservices for the API and Analysis Engine.
- **Intelligence**: Implement a "Feedback Loop" where user-reported false positives are used to retrain the Weka models automatically.
