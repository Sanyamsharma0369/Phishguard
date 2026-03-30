package com.phishguard.utils;

/**
 * PhishGuard - Constants.java
 * -------------------------------------------------
 * Central repository for all application-wide constants.
 * Avoids magic numbers/strings scattered across the codebase.
 *
 * Usage: Constants.RISK_THRESHOLD_HIGH  (no instantiation needed)
 */
public final class Constants {

    // ── Prevent instantiation ──────────────────────────────────────────
    private Constants() {
        throw new UnsupportedOperationException("Constants is a utility class.");
    }

    // ── Application Identity ───────────────────────────────────────────
    public static final String APP_NAME    = "PhishGuard";
    public static final String APP_VERSION = "1.0.0";
    public static final String APP_AUTHOR  = "PhishGuard Security Team";

    // ── Risk Score Weights (must sum to 1.0) ──────────────────────────
    /** Weight for Sender Reputation score */
    public static final double WEIGHT_SENDER    = 0.20;
    /** Weight for NLP Text Analysis score */
    public static final double WEIGHT_TEXT      = 0.15;
    /** Weight for AI Model (Weka ensemble) score */
    public static final double WEIGHT_AI_MODEL  = 0.40;
    /** Weight for Threat Intelligence score */
    public static final double WEIGHT_THREAT    = 0.15;
    /** Weight for Visual CNN Analysis score */
    public static final double WEIGHT_VISUAL    = 0.10;

    // ── Risk Thresholds (overridden by config.properties) ─────────────
    public static final double DEFAULT_THRESHOLD_HIGH       = 0.85;
    public static final double DEFAULT_THRESHOLD_SUSPICIOUS = 0.50;

    // ── AI Model Trigger Threshold ─────────────────────────────────────
    /** Threat Intel + Visual Analysis only run if aiModelScore exceeds this */
    public static final double THREAT_INTEL_TRIGGER = 0.70;

    // ── Email Monitoring ───────────────────────────────────────────────
    public static final long   DEFAULT_POLL_INTERVAL_MS = 60_000L;  // 60 seconds
    public static final String IMAP_PROTOCOL             = "imaps";
    public static final String MAIL_FOLDER_INBOX         = "INBOX";

    // ── WHOIS / Domain Age ─────────────────────────────────────────────
    public static final int WHOIS_MIN_DOMAIN_AGE_DAYS = 30;

    // ── Entropy Bounds ─────────────────────────────────────────────────
    /** URLs with entropy above this are considered highly obfuscated */
    public static final double HIGH_ENTROPY_THRESHOLD = 3.5;

    // ── URL Feature Array Indices (8 features for Weka) ───────────────
    public static final int FEAT_URL_LENGTH      = 0;
    public static final int FEAT_HAS_HTTPS       = 1;
    public static final int FEAT_HAS_IP          = 2;
    public static final int FEAT_KEYWORD_COUNT   = 3;
    public static final int FEAT_DOT_COUNT       = 4;
    public static final int FEAT_SPECIAL_CHARS   = 5;
    public static final int FEAT_ENTROPY         = 6;
    public static final int FEAT_SUBDOMAIN_COUNT = 7;
    public static final int FEATURE_COUNT        = 8;

    // ── Decision Outcomes ──────────────────────────────────────────────
    public static final String DECISION_HIGH_RISK   = "HIGH_RISK";
    public static final String DECISION_SUSPICIOUS  = "SUSPICIOUS";
    public static final String DECISION_SAFE        = "SAFE";

    // ── Actions Taken ──────────────────────────────────────────────────
    public static final String ACTION_BLOCKED  = "BLOCKED";
    public static final String ACTION_WARNED   = "WARNED";
    public static final String ACTION_ALLOWED  = "ALLOWED";

    // ── Log Severity Levels ────────────────────────────────────────────
    public static final String SEV_INFO     = "INFO";
    public static final String SEV_WARNING  = "WARNING";
    public static final String SEV_ERROR    = "ERROR";
    public static final String SEV_CRITICAL = "CRITICAL";

    // ── Database Table Names ───────────────────────────────────────────
    public static final String TABLE_INCIDENTS   = "incidents";
    public static final String TABLE_QUARANTINE  = "quarantine";
    public static final String TABLE_LOGS        = "logs";
    public static final String TABLE_DAILY_STATS = "daily_stats";

    // ── API Endpoints ──────────────────────────────────────────────────
    public static final String PHISHTANK_API_URL  = "https://checkurl.phishtank.com/checkurl/";
    public static final String VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls";

    // ── Resource Paths (classpath-relative) ───────────────────────────
    public static final String KEYWORDS_FILE        = "/keywords.txt";
    public static final String CONFIG_FILE          = "/config.properties";
    public static final String MODEL_NAIVE_BAYES    = "/models/naivebayes.model";
    public static final String MODEL_RANDOM_FOREST  = "/models/randomforest.model";

    // ── GUI ────────────────────────────────────────────────────────────
    public static final int    WINDOW_WIDTH  = 1200;
    public static final int    WINDOW_HEIGHT = 750;
    public static final String FONT_MAIN     = "Segoe UI";

    // ── HTTP Timeouts (milliseconds) ───────────────────────────────────
    public static final int HTTP_CONNECT_TIMEOUT_MS = 5_000;
    public static final int HTTP_READ_TIMEOUT_MS    = 10_000;

    // ── Quarantine ─────────────────────────────────────────────────────
    /** Domain stays quarantined for this many days before auto-expiry (future feature) */
    public static final int QUARANTINE_EXPIRY_DAYS = 90;

    // ── Phase 2 Aliases (spec-named constants) ─────────────────────────
    /** Alias: finalScore >= this → HIGH_RISK (same as DEFAULT_THRESHOLD_HIGH) */
    public static final double RISK_THRESHOLD_HIGH       = DEFAULT_THRESHOLD_HIGH;
    /** Alias: finalScore >= this → SUSPICIOUS (same as DEFAULT_THRESHOLD_SUSPICIOUS) */
    public static final double RISK_THRESHOLD_SUSPICIOUS = DEFAULT_THRESHOLD_SUSPICIOUS;
    /** Alias: Threat Intel weight (same as WEIGHT_THREAT) */
    public static final double WEIGHT_THREAT_INTEL       = WEIGHT_THREAT;

    /** URLs longer than this number of characters are penalized */
    public static final int URL_LENGTH_THRESHOLD    = 75;
    /** Domains with more than this many subdomains are suspicious */
    public static final int MAX_SUBDOMAIN_COUNT     = 3;
    /** Score bump if URL body contains at least this many suspicious keywords */
    public static final int SUSPICIOUS_KEYWORD_THRESHOLD = 2;

    /** Classpath path to NaiveBayes Weka model */
    public static final String MODEL_PATH_NB       = MODEL_NAIVE_BAYES;
    /** Classpath path to Random Forest Weka model */
    public static final String MODEL_PATH_RF       = MODEL_RANDOM_FOREST;
}
