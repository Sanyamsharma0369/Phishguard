package com.phishguard.engine;

import java.util.*;

/**
 * ExplainabilityEngine — Converts raw detection signals into human-readable 
 * explanations. Identifies specific "red flags" and "safe signals".
 */
public class ExplainabilityEngine {

    public record Explanation(
        List<String> redFlags,      // HIGH severity reasons
        List<String> yellowFlags,   // MEDIUM severity reasons
        List<String> greenFlags,    // Reasons it might be safe
        String summary,             // One-line human readable summary
        int totalRedFlags
    ) {}

    public static Explanation explain(
        String url,
        String sender,
        double vtScore,
        int vtPositives,
        int vtTotal,
        boolean ptIsPhishing,
        boolean ptVerified,
        double mlScore,
        double cnnScore,
        List<String> triggeredKeywords
    ) {
        List<String> red    = new ArrayList<>();
        List<String> yellow = new ArrayList<>();
        List<String> green  = new ArrayList<>();

        // ── VirusTotal ────────────────────────────────────────────────────────
        if (vtPositives > 10) {
            red.add("VirusTotal: " + vtPositives + "/" + vtTotal + 
                    " antivirus engines flagged this URL");
        } else if (vtPositives > 0) {
            yellow.add("VirusTotal: " + vtPositives + "/" + vtTotal + 
                       " engines flagged (low count)");
        } else if (vtTotal > 0) {
            green.add("VirusTotal: 0/" + vtTotal + " engines flagged");
        }

        // ── PhishTank ─────────────────────────────────────────────────────────
        if (ptIsPhishing && ptVerified) {
            red.add("PhishTank: URL found in verified phishing database (community confirmed)");
        } else if (ptIsPhishing) {
            red.add("PhishTank: URL found in phishing database (unverified)");
        } else {
            green.add("PhishTank: URL not found in phishing database");
        }

        // ── ML Score ──────────────────────────────────────────────────────────
        if (mlScore >= 0.75) {
            red.add(String.format(
                "ML Model: RandomForest + Naive Bayes ensemble scored %.1f%% phishing probability",
                mlScore * 100));
        } else if (mlScore >= 0.50) {
            yellow.add(String.format(
                "ML Model: Moderate phishing probability (%.1f%%)", mlScore * 100));
        } else {
            green.add(String.format(
                "ML Model: Low phishing probability (%.1f%%)", mlScore * 100));
        }

        // ── CNN Visual Score ──────────────────────────────────────────────────
        if (cnnScore >= 0.75) {
            red.add(String.format(
                "CNN Visual Analysis: Screenshot analysis shows %.1f%% visual similarity to known phishing pages",
                cnnScore * 100));
        } else if (cnnScore >= 0.50) {
            yellow.add(String.format(
                "CNN Visual: Moderate visual phishing similarity (%.1f%%)", cnnScore * 100));
        } else if (cnnScore > 0) {
            green.add("CNN Visual: Page does not visually resemble known phishing pages");
        }

        // ── Keywords ─────────────────────────────────────────────────────────
        if (triggeredKeywords != null && !triggeredKeywords.isEmpty()) {
            if (triggeredKeywords.size() >= 3) {
                red.add("Suspicious keywords detected: \"" +
                    String.join("\", \"", triggeredKeywords) + "\"");
            } else {
                yellow.add("Suspicious keyword detected: \"" +
                    String.join("\", \"", triggeredKeywords) + "\"");
            }
        } else {
            green.add("No suspicious keywords found in email content");
        }

        // ── URL Structure Analysis ────────────────────────────────────────────
        if (url != null) {
            // URL length
            if (url.length() > 100) {
                red.add("URL length: " + url.length() + 
                        " characters (abnormally long — common phishing tactic)");
            } else if (url.length() > 75) {
                yellow.add("URL length: " + url.length() + " characters (slightly long)");
            }

            // Suspicious TLD
            String urlLower = url.toLowerCase();
            List<String> suspiciousTlds = List.of(".xyz", ".tk", ".ml", ".ga", ".cf", 
                                                    ".gq", ".top", ".click", ".link");
            for (String tld : suspiciousTlds) {
                if (urlLower.contains(tld)) {
                    red.add("Suspicious TLD: \"" + tld + 
                            "\" is commonly used in phishing domains");
                    break;
                }
            }

            // IP address instead of domain
            if (urlLower.matches(".*https?://\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
                red.add("IP address URL: Uses raw IP instead of domain name — strong phishing indicator");
            }

            // Excessive subdomains
            try {
                String host = new java.net.URL(url).getHost();
                long dots = host.chars().filter(c -> c == '.').count();
                if (dots >= 3) {
                    yellow.add("Excessive subdomains: " + (dots - 1) + 
                               " subdomains detected (e.g. secure.paypal.login.evil.com)");
                }
            } catch (Exception ignored) {}

            // Brand spoofing in URL
            List<String> brands = List.of("paypal", "google", "amazon", "apple", 
                                           "microsoft", "netflix", "bank", "secure");
            for (String brand : brands) {
                if (urlLower.contains(brand) && !urlLower.contains(brand + ".com")) {
                    red.add("Brand spoofing: URL contains \"" + brand + 
                            "\" but is not the official domain");
                    break;
                }
            }

            // HTTPS check
            if (!urlLower.startsWith("https")) {
                yellow.add("No HTTPS: URL uses unencrypted HTTP connection");
            } else {
                green.add("HTTPS: URL uses secure encrypted connection");
            }
        }

        // ── Sender Spoofing ───────────────────────────────────────────────────
        if (sender != null && sender.contains("@")) {
            String domain = sender.substring(sender.indexOf("@") + 1).toLowerCase();
            List<String> suspDomains = List.of("gmail.com.secure", "paypal-support",
                                                "amazon-alert", "apple-id");
            for (String susp : suspDomains) {
                if (domain.contains(susp)) {
                    red.add("Sender spoofing: \"" + domain + 
                            "\" impersonates a trusted brand");
                    break;
                }
            }
        }

        // ── Generate Summary ──────────────────────────────────────────────────
        String summary;
        int totalRed = red.size();
        if (totalRed >= 4) {
            summary = "Multiple strong phishing indicators detected (" + 
                      totalRed + " critical signals). Do not visit this URL.";
        } else if (totalRed >= 2) {
            summary = totalRed + " critical phishing signals detected. Treat with high caution.";
        } else if (totalRed == 1) {
            summary = "1 critical signal detected alongside " + 
                      yellow.size() + " warnings. Exercise caution.";
        } else if (!yellow.isEmpty()) {
            summary = "No critical signals but " + yellow.size() + 
                      " warning(s) detected. Verify before proceeding.";
        } else {
            summary = "No significant phishing indicators detected. Appears safe.";
        }

        return new Explanation(red, yellow, green, summary, totalRed);
    }
}
