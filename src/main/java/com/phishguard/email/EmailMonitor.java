package com.phishguard.email;

import com.phishguard.database.LogDAO;
import com.phishguard.detection.AIModelEngine;
import com.phishguard.engine.DecisionEngine;
import com.phishguard.engine.MitigationEngine;
import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.ConfigLoader;
import com.phishguard.utils.Constants;
import jakarta.mail.Flags;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.search.FlagTerm;
import com.phishguard.database.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.List;
import java.util.Properties;

/**
 * PhishGuard - EmailMonitor.java
 * -------------------------------------------------
 * Background daemon thread that polls the configured Gmail/Outlook inbox
 * via IMAP every N seconds (default 60s, configurable via poll.interval.ms).
 *
 * For each unread email:
 *  1. Parse sender, subject, body, URLs via EmailParser
 *  2. For each URL: run AIModelEngine + DecisionEngine
 *  3. If threat detected: log to DB, trigger MitigationEngine
 *
 * GMAIL SETUP:
 *  Gmail requires a 16-character App Password (NOT your regular password).
 *  Generate at: myaccount.google.com → Security → 2-Step Verification → App Passwords
 *  Set in config.properties:
 *    email.host=imap.gmail.com
 *    email.port=993
 *    email.user=your@gmail.com
 *    email.password=xxxx xxxx xxxx xxxx
 *
 * THREAD LIFECYCLE:
 *  Start: new Thread(new EmailMonitor()).start()
 *  Stop:  EmailMonitor.stop()
 */
public class EmailMonitor implements Runnable {

    // ── State ─────────────────────────────────────────────────────────────
    private static volatile boolean running         = false;
    private static volatile int     emailsProcessed = 0;
    private static volatile int     threatsFound    = 0;
    private static final Object     lock            = new Object();

    // ── Runnable entry point ──────────────────────────────────────────────

    @Override
    public void run() {
        running = true;
        ConfigLoader cfg       = ConfigLoader.getInstance();
        long pollIntervalMs    = cfg.getLong("poll.interval.ms", Constants.DEFAULT_POLL_INTERVAL_MS);

        System.out.println("[EmailMonitor] Started — polling every "
            + (pollIntervalMs / 1000) + "s");
        LogDAO.info("EMAIL_MONITOR", "Email monitor started. Poll interval: "
            + (pollIntervalMs / 1000) + "s");

        while (running) {
            Store store = null;
            Folder inbox = null;
            try {
                // ── Connect via IMAP ──────────────────────────────────
                store = connectToIMAP();
                inbox = store.getFolder(Constants.MAIL_FOLDER_INBOX);
                inbox.open(Folder.READ_WRITE); // Need write access to mark as SEEN

                // ── Search for unread messages ─────────────────────────
                Message[] unseen = inbox.search(
                    new FlagTerm(new Flags(Flags.Flag.SEEN), false)
                );
                System.out.println("[EmailMonitor] " + unseen.length + " unread email(s) found");

                // ── Process each unread email ──────────────────────────
                for (Message message : unseen) {
                    if (!running) break;
                    try {
                        // Get unique Message-ID header
                        String[] msgIdHeader = message.getHeader("Message-ID");
                        String messageId = (msgIdHeader != null && msgIdHeader.length > 0)
                                ? msgIdHeader[0].trim()
                                : message.getSubject() + "_" + message.getSentDate();

                        // SKIP if already processed
                        if (isAlreadyProcessed(messageId)) {
                            continue;
                        }

                        processEmail(message);

                        // After successful processing, mark as done in DB
                        markAsProcessed(messageId);

                        // Also mark as READ in Gmail
                        message.setFlag(Flags.Flag.SEEN, true);

                        synchronized (lock) { emailsProcessed++; }
                    } catch (Exception e) {
                        System.err.println("[EmailMonitor] Error processing individual email: "
                            + e.getMessage());
                        LogDAO.error("EMAIL_PROCESS_ERROR", e.getMessage());
                    }
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.out.println("[EmailMonitor] Interrupted — stopping.");
                break;

            } catch (Exception e) {
                System.err.println("[EmailMonitor] Poll error: " + e.getMessage());
                LogDAO.error("EMAIL_MONITOR_ERROR", "Poll error: " + e.getMessage());

                // Backoff: wait 30s before retry on connection failure
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
                continue; // skip the normal sleep, we already slept 30s

            } finally {
                // Always close IMAP resources cleanly
                closeQuietly(inbox);
                closeQuietly(store);
            }

            // ── Wait for next poll interval ────────────────────────────
            try {
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[EmailMonitor] Stopped. Processed: " + emailsProcessed
            + " emails, " + threatsFound + " threats found.");
        LogDAO.info("EMAIL_MONITOR", "Monitor stopped. Processed " + emailsProcessed
            + " emails, " + threatsFound + " threats found.");
    }

    // ── Per-email processing ──────────────────────────────────────────────

    /**
     * Parses and analyzes a single email message.
     * Extracts URLs and runs each through the detection pipeline.
     *
     * @param message an unread IMAP message from the open inbox folder
     */
    private void processEmail(Message message) {
        EmailParser.ParsedEmail parsed = EmailParser.parse(message);

        System.out.println("[EmailMonitor] Processing: \""
            + parsed.subject + "\" from " + parsed.senderEmail);

        List<String> urls = URLExtractor.extractAndFilter(parsed.bodyText);

        if (urls.isEmpty()) {
            System.out.println("[EmailMonitor] No URLs found — skipping");
            return;
        }

        System.out.println("[EmailMonitor] Found " + urls.size() + " URL(s) to analyze");
        for (String url : urls) {
            processURL(url, parsed);
        }
    }

    /**
     * Runs the full detection pipeline for a single URL extracted from an email.
     * Scores are computed, decision made, mitigation applied, and result logged.
     *
     * @param url    the URL to analyze
     * @param email  the parsed email that contained this URL
     */
    private void processURL(String url, EmailParser.ParsedEmail email) {
        // 1. Check manual block list FIRST
        if (DBConnection.getInstance().isManuallyBlocked(url)) {
            System.out.println("[ManualBlock] 🚫 BLOCKED (manual): " + url);
            RiskScorer scorer = new RiskScorer(url, email.senderEmail, email.subject);
            scorer.finalScore = 1.0;
            scorer.decision = "HIGH_RISK";
            scorer.actionTaken = "BLOCKED";
            com.phishguard.database.IncidentDAO.saveIncident(scorer);

            com.phishguard.websocket.NotificationServer.getInstance().sendThreatAlert(url, email.senderEmail, scorer.finalScore, scorer.decision);

            new Thread(() -> com.phishguard.utils.EmailAlerter.sendAlert(
                "🚨 PhishGuard: HIGH RISK URL Detected!",
                "⚠️ A HIGH RISK phishing URL was detected!\n\n" +
                "URL: " + url + "\n" +
                "Sender: " + email.senderEmail + "\n" +
                "Risk Score: " + String.format("%.4f", scorer.finalScore) + "\n" +
                "Time: " + java.time.LocalDateTime.now() + "\n\n" +
                "Action taken: BLOCKED\n\n" +
                "View dashboard: http://localhost:8080"
            )).start();

            return;
        }

        // 2. Skip whitelisted URLs entirely
        if (DBConnection.getInstance().isWhitelisted(url)) {
            System.out.println("[Whitelist] Skipping safe domain: " + url);
            return;
        }

        System.out.println("[EmailMonitor] Analyzing: " + url);

        try {
            RiskScorer scorer = new RiskScorer(url, email.senderEmail, email.subject);

            // Layer 3: AI model score (other layers added in Phase 4)
            scorer.aiModelScore = AIModelEngine.predict(url);

            // Compute weighted final score and classify
            DecisionEngine.decide(scorer);

            System.out.println("[EmailMonitor] → " + scorer.decision
                + " | Score: " + String.format("%.4f", scorer.finalScore));

            // Track threat count
            if (!Constants.DECISION_SAFE.equals(scorer.decision)) {
                synchronized (lock) { threatsFound++; }
                LogDAO.warning("THREAT_DETECTED", scorer.getSummary());
                
                if ("HIGH_RISK".equals(scorer.decision)) {
                    com.phishguard.websocket.NotificationServer.getInstance().sendThreatAlert(url, email.senderEmail, scorer.finalScore, scorer.decision);
                    new Thread(() -> com.phishguard.utils.EmailAlerter.sendAlert(
                        "🚨 PhishGuard: HIGH RISK URL Detected!",
                        "⚠️ A HIGH RISK phishing URL was detected!\n\n" +
                        "URL: " + url + "\n" +
                        "Sender: " + email.senderEmail + "\n" +
                        "Risk Score: " + String.format("%.4f", scorer.finalScore) + "\n" +
                        "Time: " + java.time.LocalDateTime.now() + "\n\n" +
                        "Action taken: BLOCKED\n\n" +
                        "View dashboard: http://localhost:8080"
                    )).start();
                } else if ("SUSPICIOUS".equals(scorer.decision)) {
                    com.phishguard.websocket.NotificationServer.getInstance().sendNewIncident(url, scorer.decision, scorer.finalScore);
                }
            } else {
                com.phishguard.websocket.NotificationServer.getInstance().sendNewIncident(url, scorer.decision, scorer.finalScore);
            }

            // Apply mitigation (stub in Phase 3, full in Phase 6)
            MitigationEngine.mitigate(scorer);

        } catch (Exception e) {
            System.err.println("[EmailMonitor] Error analyzing URL '" + url + "': "
                + e.getMessage());
            LogDAO.error("URL_ANALYSIS_ERROR", "URL: " + url + " | " + e.getMessage());
        }
    }

    // ── IMAP connection ───────────────────────────────────────────────────

    /**
     * Establishes an IMAP/IMAPS connection to the configured mail server.
     *
     * Gmail notes:
     *  - Requires a 16-character App Password (NOT your Google account password)
     *  - Generate at: myaccount.google.com → Security → App Passwords
     *  - Set email.password=xxxx xxxx xxxx xxxx in config.properties
     *
     * @return an open (connected) Jakarta Mail Store
     * @throws Exception if connection fails
     */
    private Store connectToIMAP() throws Exception {
        ConfigLoader cfg = ConfigLoader.getInstance();

        Properties props = new Properties();
        props.put("mail.store.protocol",          Constants.IMAP_PROTOCOL);
        props.put("mail.imaps.host",              cfg.get("email.host", "imap.gmail.com"));
        props.put("mail.imaps.port",              cfg.get("email.port", "993"));
        props.put("mail.imaps.ssl.enable",        "true");
        props.put("mail.imaps.ssl.trust",         "*");
        props.put("mail.imaps.connectiontimeout", "30000");
        props.put("mail.imaps.timeout",           "30000");

        Session session = Session.getInstance(props);
        Store store = session.getStore(Constants.IMAP_PROTOCOL);

        store.connect(
            cfg.get("email.host",     "imap.gmail.com"),
            cfg.get("email.user",     ""),
            cfg.get("email.password", "")
        );

        System.out.println("[EmailMonitor] IMAP connected to "
            + cfg.get("email.host") + " as " + cfg.get("email.user"));
        return store;
    }

    // ── Lifecycle control ─────────────────────────────────────────────────

    /** Signals the monitor to stop after the current poll cycle completes. */
    public static void stop() {
        running = false;
        System.out.println("[EmailMonitor] Stop signal received.");
    }

    /** @return total number of emails processed since monitor started */
    public static int getEmailsProcessed() {
        return emailsProcessed;
    }

    /** @return total number of SUSPICIOUS or HIGH_RISK URLs detected */
    public static int getThreatsFound() {
        return threatsFound;
    }

    /** @return true if the monitor is currently running */
    public static boolean isRunning() {
        return running;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static void closeQuietly(Folder folder) {
        try {
            if (folder != null && folder.isOpen()) folder.close(false);
        } catch (Exception ignored) {}
    }

    private static void closeQuietly(Store store) {
        try {
            if (store != null && store.isConnected()) store.close();
        } catch (Exception ignored) {}
    }

    // ── Deduplication Helpers ─────────────────────────────────────────────

    private boolean isAlreadyProcessed(String messageId) {
        String sql = "SELECT 1 FROM processed_emails WHERE message_id = ?";
        try (Connection conn = DBConnection.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, messageId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (Exception e) {
            // If DB error, process it anyway (safe default)
            return false;
        }
    }

    private void markAsProcessed(String messageId) {
        String sql = "INSERT IGNORE INTO processed_emails (message_id) VALUES (?)";
        try (Connection conn = DBConnection.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, messageId);
            ps.executeUpdate();
        } catch (Exception e) {
            System.err.println("[EmailMonitor] Could not mark email as processed: " + e.getMessage());
        }
    }
}
