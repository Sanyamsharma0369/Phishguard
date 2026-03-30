package com.phishguard.api;

import com.phishguard.utils.ConfigLoader;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * PhishGuard - VirusTotalAPI.java
 * -------------------------------------------------
 * Layer 4b — Scans a URL against 70+ security engines via VirusTotal's
 * public API v2 URL report endpoint.
 *
 * Returns the number of AV engines that flagged the URL as malicious.
 * This count is then converted to a 0.0–1.0 score by getScore().
 *
 * DEMO MODE: Simulates realistic detection counts when no API key is set.
 *
 * REAL API KEY SETUP:
 *   1. Register at: https://www.virustotal.com/gui/join-us
 *   2. Get your API key from: https://www.virustotal.com/gui/my-apikey
 *   3. Set in config.properties: virustotal.api.key=YOUR_REAL_KEY
 *   Note: Free tier allows 4 requests/minute.
 */
public final class VirusTotalAPI {

    private VirusTotalAPI() {}

    private static final String SCAN_URL   = "https://www.virustotal.com/vtapi/v2/url/report";
    private static final int    TIMEOUT_MS = 8_000;

    private static String  apiKey   = null;
    private static boolean demoMode = false;

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Loads API key from config and sets demo mode if absent.
     * Must be called once at startup via ThreatIntelChecker.initialize().
     */
    public static void initialize() {
        try {
            apiKey = ConfigLoader.getInstance().get("virustotal.api.key", "");
        } catch (Exception e) {
            apiKey = "";
        }

        if (apiKey == null || apiKey.isBlank()
                || apiKey.toUpperCase().startsWith("YOUR_")) {
            demoMode = true;
            System.out.println("[VirusTotal] API key not configured — running in demo mode");
        } else {
            demoMode = false;
            System.out.println("[VirusTotal] API key loaded, live mode active");
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Returns the number of AV engines that flagged this URL as malicious.
     *
     * @param url the URL to check
     * @return number of engines detecting malicious content (0 = clean)
     *         Returns 0 on any API error (fail-open).
     */
    public static int getMaliciousCount(String url) {
        if (url == null || url.isBlank()) return 0;
        if (demoMode) return simulateDemoMode(url);

        try {
            // Build GET request with URL parameter
            String encoded    = URLEncoder.encode(url, StandardCharsets.UTF_8);
            String requestUrl = SCAN_URL + "?apikey=" + apiKey + "&resource=" + encoded;

            URL apiUrl = new URL(requestUrl);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "phishguard/1.0");

            int status = conn.getResponseCode();
            if (status != 200) {
                System.err.println("[VirusTotal] HTTP " + status);
                conn.disconnect();
                return 0;
            }

            String response = readStream(conn.getInputStream());
            conn.disconnect();

            // Parse "positives" and "total" from JSON
            int positives = extractJsonInt(response, "positives");
            int total     = extractJsonInt(response, "total");

            System.out.println("[VirusTotal] " + positives + "/" + total
                + " engines flagged " + url);
            return positives;

        } catch (Exception e) {
            System.err.println("[VirusTotal] API error: " + e.getMessage() + " — defaulting to 0");
            return 0; // fail-open
        }
    }

    /**
     * Converts the raw malicious count to a normalized 0.0–1.0 risk score.
     *
     * Scoring tiers:
     *   0 engines  → 0.0 (clean)
     *   1–3 engines → 0.3 (possibly malicious)
     *   4–7 engines → 0.6 (likely malicious)
     *   8–15 engines → 0.85 (highly malicious)
     *   >15 engines → 1.0 (confirmed malicious)
     *
     * @param url the URL to score
     * @return risk score between 0.0 and 1.0
     */
    public static double getScore(String url) {
        int count = getMaliciousCount(url);
        if (count == 0)        return 0.0;
        if (count <= 3)        return 0.3;
        if (count <= 7)        return 0.6;
        if (count <= 15)       return 0.85;
        return 1.0;
    }

    /** @return true if running without a real API key */
    public static boolean isDemoMode() {
        return demoMode;
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Simulates VirusTotal detection counts based on URL patterns.
     * Called when no API key is configured.
     */
    private static int simulateDemoMode(String url) {
        String lower = url.toLowerCase();

        boolean isSuspicious =
            lower.contains("verify")  || lower.contains("login")   ||
            lower.contains("secure")  || lower.contains("account") ||
            lower.contains("update")  || lower.contains("confirm");

        boolean isKnownSafe =
            lower.contains("google") || lower.contains("microsoft") ||
            lower.contains("apple.com") || lower.contains("amazon.com");

        if (isSuspicious && !isKnownSafe) {
            System.out.println("[VirusTotal] DEMO MODE — simulated 8/72 detections");
            return 8;
        }
        System.out.println("[VirusTotal] DEMO MODE — no detections");
        return 0;
    }

    /** Reads all bytes from an InputStream and returns as UTF-8 string. */
    private static String readStream(InputStream is) throws Exception {
        byte[] buffer = new byte[4096];
        StringBuilder sb = new StringBuilder();
        int n;
        while ((n = is.read(buffer)) != -1) {
            sb.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    /**
     * Extracts an integer field value from a simple JSON string.
     * Does NOT use any JSON library — just string parsing.
     * Handles: "positives": 8 or "positives":8
     *
     * @param json  the JSON response string
     * @param field the field name to extract
     * @return the integer value, or 0 if not found or parse fails
     */
    private static int extractJsonInt(String json, String field) {
        try {
            String key   = "\"" + field + "\"";
            int    idx   = json.indexOf(key);
            if (idx < 0) return 0;
            int    colon = json.indexOf(":", idx + key.length());
            if (colon < 0) return 0;
            // Read digits after the colon (skip spaces)
            StringBuilder num = new StringBuilder();
            for (int i = colon + 1; i < json.length(); i++) {
                char ch = json.charAt(i);
                if (Character.isDigit(ch)) {
                    num.append(ch);
                } else if (ch != ' ' && num.length() == 0) {
                    continue; // skip leading spaces
                } else if (num.length() > 0) {
                    break; // stop at first non-digit after reading digits
                }
            }
            return num.length() > 0 ? Integer.parseInt(num.toString()) : 0;
        } catch (Exception e) {
            return 0;
        }
    }
}
