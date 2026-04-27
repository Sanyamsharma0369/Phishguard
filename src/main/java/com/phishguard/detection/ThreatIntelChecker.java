package com.phishguard.detection;

import com.phishguard.utils.PhishTankChecker;
import com.phishguard.utils.VirusTotalChecker;

/**
 * PhishGuard - ThreatIntelChecker.java
 * -------------------------------------------------
 * Layer 4 coordinator — orchestrates PhishTank and VirusTotal API calls
 * and returns a single combined threat intelligence score (0.0–1.0).
 *
 * Scoring logic:
 *   - PhishTank confirmed phishing → combined score = max(current, 0.95)
 *   - VirusTotal raw score            → combined score = max(current, vtScore)
 *
 * PhishTank takes precedence (community-verified database).
 * Result is the maximum of both signals, never less than either.
 *
 * Both APIs support DEMO MODE when no keys are configured.
 */
public final class ThreatIntelChecker {

    private ThreatIntelChecker() {}

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Initializes both PhishTank and VirusTotal APIs.
     * Must be called once at application startup.
     */
    public static void initialize() {
        System.out.println("[ThreatIntel] Initialized (PhishTank + VirusTotal with Caching)");
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Checks a URL against both PhishTank and VirusTotal and returns a
     * combined threat intelligence score.
     *
     * If PhishTank confirms it as phishing (community-verified), the score
     * is set to 0.95 regardless of the VirusTotal result.
     * VirusTotal's score then raises it further if applicable.
     *
     * @param url the URL to check
     * @return combined threat score 0.0–1.0 (0=clean, 1=confirmed phishing)
     */
    public static double check(String url) {
        if (url == null || url.isBlank()) return 0.0;

        boolean phishTankPositive  = PhishTankChecker.check(url).isPhishing();
        double  virusTotalScore    = VirusTotalChecker.check(url).score();

        double combinedScore = 0.0;
        if (phishTankPositive) {
            combinedScore = Math.max(combinedScore, 0.95);
        }
        combinedScore = Math.max(combinedScore, virusTotalScore);

        System.out.println("[ThreatIntel] URL: " + url);
        System.out.println("  PhishTank: " + phishTankPositive
            + " | VirusTotal: " + String.format("%.2f", virusTotalScore));
        System.out.println("  Combined threat score: "
            + String.format("%.4f", combinedScore));

        return combinedScore;
    }

    /**
     * Returns true if PhishTank has this URL in its verified phishing database.
     * Useful for auto-quarantine decisions in MitigationEngine.
     *
     * @param url the URL to check
     * @return true if PhishTank-confirmed phishing
     */
    public static boolean isConfirmedPhishing(String url) {
        return PhishTankChecker.check(url).isPhishing();
    }
}
