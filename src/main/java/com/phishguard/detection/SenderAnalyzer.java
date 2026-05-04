package com.phishguard.detection;

import com.phishguard.utils.WhoisChecker;

import java.util.Arrays;
import java.util.List;

/**
 * PhishGuard - SenderAnalyzer.java
 * -------------------------------------------------
 * Layer 1 — Analyzes email sender for reputation signals.
 *
 * Five signals each contribute to a 0.0–1.0 risk score:
 *   1. Display name vs actual sending domain mismatch (+0.30)
 *   2. Domain age < 30 days via WHOIS lookup (+0.35, +0.10 if < 7 days)
 *   3. Freemail domain impersonating a brand (+0.25)
 *   4. Typosquatting detection using Levenshtein distance (+0.20)
 *   5. Suspicious TLD (.xyz, .tk, .ml, etc.) (+0.15)
 *
 * Score is capped at 1.0.
 */
public final class SenderAnalyzer {

    private SenderAnalyzer() {}

    // ── Domain/Brand Lists ────────────────────────────────────────────────

    private static final List<String> FREEMAIL_DOMAINS = Arrays.asList(
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "protonmail.com", "yopmail.com", "tempmail.com",
        "guerrillamail.com", "mailinator.com"
    );

    private static final List<String> TRUSTED_BRANDS = Arrays.asList(
        "paypal", "amazon", "google", "microsoft", "apple",
        "netflix", "facebook", "sbi", "hdfc", "icici",
        "axis", "paytm", "flipkart", "instagram", "whatsapp"
    );

    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".cn"
    );

    // ── Scoring Weights ───────────────────────────────────────────────────
    private static final double W_DISPLAY_NAME_MISMATCH = 0.30;
    private static final double W_DOMAIN_AGE_YOUNG      = 0.35;
    private static final double W_DOMAIN_AGE_VERY_NEW   = 0.10;
    private static final double W_FREEMAIL_BRAND        = 0.25;
    private static final double W_TYPOSQUATTING         = 0.20;
    private static final double W_SUSPICIOUS_TLD        = 0.15;

    // ── Thread-local state for reporting ─────────────────────────────────
    /** Signals fired during last analysis — for report generation */
    private static final ThreadLocal<StringBuilder> lastReport =
        ThreadLocal.withInitial(StringBuilder::new);

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Analyzes sender reputation and returns a risk score 0.0–1.0.
     *
     * @param senderEmail full email address (e.g., support@secure-paypal.xyz)
     * @param displayName plain text From: display name (e.g., "PayPal Support")
     * @return risk score between 0.0 (safe) and 1.0 (high risk)
     */
    public static double analyze(String senderEmail, String displayName) {
        if (senderEmail == null || senderEmail.isBlank()) return 0.0;

        StringBuilder report = new StringBuilder();
        double score = 0.0;

        String domain       = extractDomain(senderEmail);
        String domainLower  = domain.toLowerCase();
        String displayLower = (displayName != null) ? displayName.toLowerCase() : "";

        // ── Signal 1: Display name contains brand, but domain doesn't ──
        for (String brand : TRUSTED_BRANDS) {
            if (displayLower.contains(brand) && !domainLower.contains(brand)) {
                score += W_DISPLAY_NAME_MISMATCH;
                report.append("  ✗ Display name brand mismatch: '")
                    .append(brand).append("' in name but not in domain\n");
                break; // only count once
            }
        }

        // ── Signal 2: Domain age via WhoisChecker ──────────────────────────────
        WhoisChecker.WhoisResult whoisRes = WhoisChecker.check(domain);
        int ageDays = whoisRes.ageDays();
        System.out.println("[SenderAnalyzer] Domain age: " + ageDays + " days");
        if (ageDays < 30) {
            score += W_DOMAIN_AGE_YOUNG;
            report.append("  ✗ Domain very new: ").append(ageDays).append(" days old\n");
            if (ageDays < 7) {
                score += W_DOMAIN_AGE_VERY_NEW;
                report.append("  ✗ Domain EXTREMELY new (< 7 days) — extra penalty\n");
            }
        }

        // ── Signal 3: Freemail domain impersonating brand ───────────────
        if (FREEMAIL_DOMAINS.contains(domainLower)) {
            for (String brand : TRUSTED_BRANDS) {
                if (displayLower.contains(brand)) {
                    score += W_FREEMAIL_BRAND;
                    report.append("  ✗ Brand '").append(brand)
                        .append("' claimed via freemail (").append(domain).append(")\n");
                    break;
                }
            }
        }

        // ── Signal 4: Typosquatting via Levenshtein distance ────────────
        String domainRoot = domainLower.replaceAll("\\.[a-z]{2,}$", "")
                                       .replaceAll("-", "")
                                       .replace("0", "o").replace("1", "l");
        for (String brand : TRUSTED_BRANDS) {
            if (!domainLower.equals(brand + ".com") && !domainLower.equals(brand + ".in")) {
                int dist = levenshtein(domainRoot, brand);
                if (dist <= 2 && dist > 0 && domainLower.contains(brand.substring(0, Math.min(3, brand.length())))) {
                    score += W_TYPOSQUATTING;
                    System.out.println("[SenderAnalyzer] Possible typosquatting: "
                        + domain + " ~ " + brand);
                    report.append("  ✗ Typosquatting detected: '")
                        .append(domain).append("' resembles '").append(brand).append("'\n");
                    break;
                }
            }
        }

        // ── Signal 5: Suspicious TLD ────────────────────────────────────
        for (String tld : SUSPICIOUS_TLDS) {
            if (domainLower.endsWith(tld)) {
                score += W_SUSPICIOUS_TLD;
                report.append("  ✗ Suspicious TLD: ").append(tld).append("\n");
                break;
            }
        }

        // ── Cap and log ─────────────────────────────────────────────────
        score = Math.min(1.0, score);
        System.out.printf("[SenderAnalyzer] %s → score: %.4f%n", senderEmail, score);

        lastReport.get().setLength(0);
        lastReport.get().append(report);

        return score;
    }

    /**
     * Returns a human-readable analysis report showing which signals fired.
     * Call immediately after {@link #analyze(String, String)} on the same thread.
     *
     * @param senderEmail  same email passed to analyze()
     * @param displayName  same display name passed to analyze()
     * @return multi-line report string
     */
    public static String getAnalysisReport(String senderEmail, String displayName) {
        String domain = extractDomain(senderEmail);
        WhoisChecker.WhoisResult whoisRes = WhoisChecker.check(domain);
        int ageDays = whoisRes.ageDays();

        StringBuilder sb = new StringBuilder();
        sb.append("SenderAnalyzer Report:\n");
        sb.append("  Email       : ").append(senderEmail).append("\n");
        sb.append("  Display     : ").append(displayName).append("\n");
        sb.append("  Domain      : ").append(domain).append("\n");
        sb.append("  Domain Age  : ").append(ageDays).append(" days\n");
        sb.append("Signals fired:\n");
        sb.append(lastReport.get().length() > 0 ? lastReport.get() : "  (none)\n");
        return sb.toString();
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Extracts the domain from a full email address.
     * "support@paypal-secure.xyz" → "paypal-secure.xyz"
     */
    private static String extractDomain(String email) {
        try {
            int atIdx = email.lastIndexOf('@');
            if (atIdx < 0 || atIdx == email.length() - 1) return "";
            return email.substring(atIdx + 1).trim().toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Computes the Levenshtein (edit) distance between two strings.
     * Standard dynamic-programming O(n*m) implementation.
     * Used for typosquatting detection.
     *
     * @return minimum number of single-character edits to transform a into b
     */
    static int levenshtein(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        int la = a.length(), lb = b.length();
        int[][] dp = new int[la + 1][lb + 1];

        for (int i = 0; i <= la; i++) dp[i][0] = i;
        for (int j = 0; j <= lb; j++) dp[0][j] = j;

        for (int i = 1; i <= la; i++) {
            for (int j = 1; j <= lb; j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1),
                    dp[i-1][j-1] + cost
                );
            }
        }
        return dp[la][lb];
    }
}
