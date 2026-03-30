package com.phishguard.detection;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PhishGuard - TextNLPAnalyzer.java
 * -------------------------------------------------
 * Layer 2 — Analyzes email body text for phishing language patterns.
 *
 * Uses a TF-IDF inspired keyword scoring approach across four categories:
 *   URGENCY    — triggers sense of time pressure
 *   ACTION     — direct click-bait calls to action
 *   THREAT     — security breach / compromise language
 *   CREDENTIAL — requests for sensitive personal information
 *
 * Each category has per-keyword weights and a per-category maximum.
 * Scores are summed then normalized to 0.0–1.0.
 */
public final class TextNLPAnalyzer {

    private TextNLPAnalyzer() {}

    // ── Keyword Categories with weights ───────────────────────────────────

    /** Urgency keywords — create time pressure */
    private static final List<String> URGENCY_WORDS = Arrays.asList(
        "urgent", "immediately", "right away", "act now", "limited time",
        "expires soon", "24 hours", "48 hours", "account will be", "suspended",
        "terminated", "deactivated", "disabled", "locked", "restricted"
    );
    private static final double URGENCY_WEIGHT = 0.08;
    private static final double URGENCY_MAX    = 0.40;

    /** Action keywords — direct calls to click or verify */
    private static final List<String> ACTION_WORDS = Arrays.asList(
        "click here", "click the link", "click below", "verify now",
        "confirm now", "update now", "login now", "sign in here",
        "validate your", "reactivate", "restore access"
    );
    private static final double ACTION_WEIGHT = 0.06;
    private static final double ACTION_MAX    = 0.30;

    /** Threat keywords — security alert / compromise language */
    private static final List<String> THREAT_WORDS = Arrays.asList(
        "unauthorized access", "suspicious activity", "security alert",
        "security breach", "unusual sign-in", "account compromised",
        "identity verification", "billing information", "payment failed",
        "verify your identity", "confirm your details"
    );
    private static final double THREAT_WEIGHT = 0.10;
    private static final double THREAT_MAX    = 0.40;

    /** Credential keywords — requests for personal/financial data */
    private static final List<String> CREDENTIAL_WORDS = Arrays.asList(
        "password", "username", "credit card", "bank account", "social security",
        "date of birth", "billing address", "cvv", "pin number", "account number"
    );
    private static final double CREDENTIAL_WEIGHT = 0.07;
    private static final double CREDENTIAL_MAX    = 0.35;

    /** Normalization denominator = sum of all category maxes + 0.05 safety margin */
    private static final double NORMALIZATION_DIVISOR = 1.45;

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Analyzes an email body for phishing language and returns a risk score.
     *
     * @param emailBody raw plain-text email body
     * @return normalized risk score 0.0–1.0 (0=clean, 1=clearly phishing)
     */
    public static double analyze(String emailBody) {
        if (emailBody == null || emailBody.isBlank()) return 0.0;

        String lower = emailBody.toLowerCase();

        double urgencyScore    = scoreCategory(lower, URGENCY_WORDS,    URGENCY_WEIGHT,    URGENCY_MAX);
        double actionScore     = scoreCategory(lower, ACTION_WORDS,     ACTION_WEIGHT,     ACTION_MAX);
        double threatScore     = scoreCategory(lower, THREAT_WORDS,     THREAT_WEIGHT,     THREAT_MAX);
        double credentialScore = scoreCategory(lower, CREDENTIAL_WORDS, CREDENTIAL_WEIGHT, CREDENTIAL_MAX);

        double total = urgencyScore + actionScore + threatScore + credentialScore;
        double normalized = Math.min(1.0, total / NORMALIZATION_DIVISOR);

        System.out.printf("[TextNLP] Body score: %.4f | urgency=%.2f action=%.2f threat=%.2f cred=%.2f%n",
            normalized, urgencyScore, actionScore, threatScore, credentialScore);

        return normalized;
    }

    /**
     * Returns a map of every matched keyword and its match count in the body.
     * Useful for detailed evidence logging and PDF report generation.
     *
     * @param emailBody raw email body text
     * @return map of {keyword → occurrenceCount}
     */
    public static Map<String, Integer> getKeywordMatches(String emailBody) {
        if (emailBody == null) return new HashMap<>();
        String lower = emailBody.toLowerCase();

        Map<String, Integer> matches = new HashMap<>();
        for (List<String> category : Arrays.asList(
                URGENCY_WORDS, ACTION_WORDS, THREAT_WORDS, CREDENTIAL_WORDS)) {
            for (String kw : category) {
                int count = countOccurrences(lower, kw);
                if (count > 0) {
                    matches.put(kw, matches.getOrDefault(kw, 0) + count);
                }
            }
        }
        return matches;
    }

    /**
     * Returns a multi-line analysis report with per-category scores and matched keywords.
     * Suitable for log files and PDF forensic reports.
     *
     * @param emailBody raw email body
     * @return formatted report string
     */
    public static String getAnalysisReport(String emailBody) {
        if (emailBody == null || emailBody.isBlank()) {
            return "TextNLP Analysis: (empty body — score: 0.0)";
        }
        String lower = emailBody.toLowerCase();

        double u  = scoreCategory(lower, URGENCY_WORDS,    URGENCY_WEIGHT,    URGENCY_MAX);
        double a  = scoreCategory(lower, ACTION_WORDS,     ACTION_WEIGHT,     ACTION_MAX);
        double t  = scoreCategory(lower, THREAT_WORDS,     THREAT_WEIGHT,     THREAT_MAX);
        double c  = scoreCategory(lower, CREDENTIAL_WORDS, CREDENTIAL_WEIGHT, CREDENTIAL_MAX);
        double total = Math.min(1.0, (u + a + t + c) / NORMALIZATION_DIVISOR);

        StringBuilder sb = new StringBuilder();
        sb.append("TextNLP Analysis:\n");
        sb.append(String.format("  Urgency   : %.2f  (keywords: %s)%n", u,
            listMatched(lower, URGENCY_WORDS)));
        sb.append(String.format("  Action    : %.2f  (keywords: %s)%n", a,
            listMatched(lower, ACTION_WORDS)));
        sb.append(String.format("  Threat    : %.2f  (keywords: %s)%n", t,
            listMatched(lower, THREAT_WORDS)));
        sb.append(String.format("  Credential: %.2f  (keywords: %s)%n", c,
            listMatched(lower, CREDENTIAL_WORDS)));
        sb.append(String.format("  Score     : %.4f%n", total));
        return sb.toString();
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /** Scores a single keyword category, capped at the category maximum. */
    private static double scoreCategory(String body, List<String> keywords,
                                        double weightPerKw, double max) {
        double score = 0.0;
        for (String kw : keywords) {
            if (body.contains(kw)) {
                score += weightPerKw;
                if (score >= max) return max;
            }
        }
        return score;
    }

    /** Counts non-overlapping occurrences of {@code kw} in {@code text}. */
    private static int countOccurrences(String text, String kw) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(kw, idx)) != -1) {
            count++;
            idx += kw.length();
        }
        return count;
    }

    /** Returns a comma-separated list of keywords found in the text. */
    private static String listMatched(String body, List<String> keywords) {
        StringBuilder sb = new StringBuilder();
        for (String kw : keywords) {
            if (body.contains(kw)) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(kw);
            }
        }
        return sb.length() > 0 ? sb.toString() : "none";
    }
}
