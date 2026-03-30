package com.phishguard.detection;

import com.phishguard.utils.ConfigLoader;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * PhishGuard - VisualAnalyzer.java
 * -------------------------------------------------
 * Layer 5 — Screenshot + CNN brand impersonation detection.
 *
 * ARCHITECTURE:
 *   1. Check if Flask CNN microservice is running (/health endpoint)
 *   2. If yes → POST screenshot request, parse JSON response
 *   3. If no  → Smart simulation based on URL brand pattern matching
 *
 * The simulation is NOT a simple stub — it implements the actual brand
 * database and domain matching logic that the real CNN would verify.
 * Phase 9 will replace only the image capture + CNN call parts.
 *
 * FLASK SETUP (Phase 9):
 *   cd python-cnn-service && pip install flask && python app.py
 *   Set: cnn.service.url=http://localhost:5000/analyze in config.properties
 */
public final class VisualAnalyzer {

    private VisualAnalyzer() {}

    // ── Brand Database ────────────────────────────────────────────────────

    /** Maps official brand names to their trusted domains */
    private static final Map<String, String[]> BRAND_DOMAINS;

    static {
        BRAND_DOMAINS = new HashMap<>();
        BRAND_DOMAINS.put("PayPal",    new String[]{"paypal.com"});
        BRAND_DOMAINS.put("SBI",       new String[]{"onlinesbi.sbi", "sbi.co.in"});
        BRAND_DOMAINS.put("HDFC",      new String[]{"hdfcbank.com", "netbanking.hdfcbank.com"});
        BRAND_DOMAINS.put("ICICI",     new String[]{"icicibank.com"});
        BRAND_DOMAINS.put("Google",    new String[]{"google.com", "accounts.google.com"});
        BRAND_DOMAINS.put("Microsoft", new String[]{"microsoft.com", "login.microsoftonline.com"});
        BRAND_DOMAINS.put("Amazon",    new String[]{"amazon.com", "amazon.in"});
        BRAND_DOMAINS.put("Apple",     new String[]{"apple.com", "appleid.apple.com"});
        BRAND_DOMAINS.put("Netflix",   new String[]{"netflix.com"});
        BRAND_DOMAINS.put("Facebook",  new String[]{"facebook.com", "fb.com"});
    }

    // ── Inner result class ────────────────────────────────────────────────

    /**
     * Encapsulates the result of a visual brand impersonation analysis.
     * Shared with MitigationEngine and RiskScorer for downstream decisions.
     */
    public static class VisualResult {
        /** Detected brand name, e.g. "PayPal" or "Unknown" */
        public String  detectedBrand   = "Unknown";
        /** CNN confidence level (0.0–1.0) */
        public double  confidence      = 0.0;
        /** True if brand detected but domain does NOT match the brand's official domains */
        public boolean isPhishing      = false;
        /** Actual domain parsed from the analyzed URL */
        public String  actualDomain    = "";
        /** Expected official domain for the detected brand */
        public String  expectedDomain  = "";
        /** Final visual risk score (used in RiskScorer.visualScore) */
        public double  score           = 0.0;

        /**
         * Returns a concise single-line summary of the visual analysis result.
         * Used in logs and the detailed risk breakdown table.
         */
        public String getSummary() {
            if ("Unknown".equals(detectedBrand)) {
                return "Visual: No brand pattern detected";
            }
            return "Visual: " + detectedBrand
                + " (" + String.format("%.0f%%", confidence * 100) + " confidence)"
                + (isPhishing ? " ← DOMAIN MISMATCH" : " ← OK");
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Analyzes a URL for visual brand impersonation.
     *
     * Tries the Flask CNN microservice first (Phase 9).
     * Falls back to URL pattern-based simulation when Flask is unavailable.
     *
     * @param url the URL to analyze
     * @return VisualResult with brand, confidence, isPhishing, and score
     */
    public static VisualResult analyze(String url) {
        VisualResult result = new VisualResult();
        result.actualDomain = extractDomain(url);

        try {
            if (isFlaskServiceRunning()) {
                return callFlaskService(url);
            } else {
                return simulateVisualAnalysis(url);
            }
        } catch (Exception e) {
            System.err.println("[VisualAnalyzer] Error: " + e.getMessage() + " — using simulation");
            return simulateVisualAnalysis(url);
        }
    }

    /**
     * Convenience method returning just the visual risk score.
     *
     * @param url the URL to analyze
     * @return score between 0.0 and 1.0
     */
    public static double getScore(String url) {
        return analyze(url).score;
    }

    // ── Private: Flask health check and call ──────────────────────────────

    /**
     * Probes the Flask CNN service health endpoint with a 1-second timeout.
     * Returns false (don't wait) if Flask is not running.
     */
    private static boolean isFlaskServiceRunning() {
        try {
            String baseUrl  = ConfigLoader.getInstance()
                .get("cnn.service.url", "http://localhost:5000/analyze")
                .replace("/analyze", "");
            URL healthUrl   = new URL(baseUrl + "/health");
            HttpURLConnection conn = (HttpURLConnection) healthUrl.openConnection();
            conn.setConnectTimeout(1_000);
            conn.setReadTimeout(1_000);
            conn.connect();
            boolean running = conn.getResponseCode() == 200;
            conn.disconnect();
            return running;
        } catch (Exception e) {
            return false; // not running — use simulation
        }
    }

    /**
     * Calls the Flask CNN microservice to analyze a URL's screenshot.
     * Expected JSON response:
     *   {"brand": "PayPal", "confidence": 0.91, "is_phishing": true,
     *    "expected_domain": "paypal.com"}
     *
     * This is the full real implementation — only called when Flask is running.
     */
    private static VisualResult callFlaskService(String url) {
        VisualResult result = new VisualResult();
        result.actualDomain = extractDomain(url);

        try {
            String serviceUrl = ConfigLoader.getInstance()
                .get("cnn.service.url", "http://localhost:5000/analyze");
            String postBody   = "url=" + java.net.URLEncoder.encode(url, StandardCharsets.UTF_8);
            byte[] postBytes  = postBody.getBytes(StandardCharsets.UTF_8);

            URL apiUrl = new URL(serviceUrl);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(10_000);
            conn.setReadTimeout(15_000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(postBytes);
            }

            byte[] responseBytes = conn.getInputStream().readAllBytes();
            String response      = new String(responseBytes, StandardCharsets.UTF_8);
            conn.disconnect();

            // Parse JSON response
            result.detectedBrand   = extractJsonString(response, "brand", "Unknown");
            result.confidence      = extractJsonDouble(response, "confidence", 0.0);
            result.isPhishing      = response.contains("\"is_phishing\": true")
                                  || response.contains("\"is_phishing\":true");
            result.expectedDomain  = extractJsonString(response, "expected_domain", "");
            result.score           = result.isPhishing
                                   ? Math.min(1.0, result.confidence)
                                   : result.confidence * 0.05;

            System.out.println("[VisualAnalyzer] Flask CNN: " + result.getSummary());

        } catch (Exception e) {
            System.err.println("[VisualAnalyzer] Flask call failed: " + e.getMessage());
            return simulateVisualAnalysis(url);
        }

        return result;
    }

    // ── Private: Smart simulation ─────────────────────────────────────────

    /**
     * Simulates visual analysis using URL string matching against the brand database.
     * Detects brand name in URL, then checks if the actual domain is an official one.
     *
     * This is not naïve — it replicates what the CNN would conclude:
     *   "The page LOOKS like PayPal but is hosted on paypal-verify.xyz → phishing"
     */
    private static VisualResult simulateVisualAnalysis(String url) {
        System.out.println("[VisualAnalyzer] Using simulation mode (Flask service not running)");

        VisualResult result = new VisualResult();
        result.actualDomain = extractDomain(url).toLowerCase();
        String urlLower     = url.toLowerCase();

        for (Map.Entry<String, String[]> entry : BRAND_DOMAINS.entrySet()) {
            String   brand        = entry.getKey();
            String[] trustedHosts = entry.getValue();
            String   brandLower   = brand.toLowerCase();

            if (urlLower.contains(brandLower)) {
                boolean domainIsOfficial = Arrays.asList(trustedHosts)
                    .contains(result.actualDomain);

                result.detectedBrand  = brand;
                result.confidence     = domainIsOfficial ? 0.95 : 0.91;
                result.isPhishing     = !domainIsOfficial;
                result.expectedDomain = trustedHosts[0];
                result.score          = result.isPhishing ? 0.90 : 0.05;

                System.out.println("[VisualAnalyzer] Simulated: " + result.getSummary());
                return result;
            }
        }

        // No brand detected
        result.detectedBrand = "Unknown";
        result.confidence    = 0.0;
        result.isPhishing    = false;
        result.score         = 0.0;
        System.out.println("[VisualAnalyzer] No brand pattern detected");
        return result;
    }

    // ── Private: Helpers ──────────────────────────────────────────────────

    /** Extracts the host domain from a URL string. */
    private static String extractDomain(String rawUrl) {
        try {
            String host = new URL(rawUrl).getHost();
            if (host == null) return "";
            if (host.toLowerCase().startsWith("www.")) host = host.substring(4);
            return host.toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    /** Extracts a string field from a minimal JSON string. */
    private static String extractJsonString(String json, String field, String defaultVal) {
        try {
            String key = "\"" + field + "\"";
            int idx = json.indexOf(key);
            if (idx < 0) return defaultVal;
            int colon = json.indexOf(":", idx + key.length());
            int quote1 = json.indexOf("\"", colon + 1);
            int quote2 = json.indexOf("\"", quote1 + 1);
            if (quote1 < 0 || quote2 < 0) return defaultVal;
            return json.substring(quote1 + 1, quote2);
        } catch (Exception e) {
            return defaultVal;
        }
    }

    /** Extracts a double field from a minimal JSON string. */
    private static double extractJsonDouble(String json, String field, double defaultVal) {
        try {
            String key = "\"" + field + "\"";
            int idx = json.indexOf(key);
            if (idx < 0) return defaultVal;
            int colon = json.indexOf(":", idx + key.length());
            StringBuilder num = new StringBuilder();
            for (int i = colon + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (Character.isDigit(c) || c == '.' || c == '-') num.append(c);
                else if (num.length() > 0 && c != ' ') break;
            }
            return num.length() > 0 ? Double.parseDouble(num.toString()) : defaultVal;
        } catch (Exception e) {
            return defaultVal;
        }
    }
}
