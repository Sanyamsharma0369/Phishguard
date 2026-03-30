package com.phishguard.api;

import com.phishguard.utils.ConfigLoader;
import com.phishguard.utils.Constants;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * PhishGuard - PhishTankAPI.java
 * -------------------------------------------------
 * Layer 4a — Checks a URL against PhishTank's community-maintained
 * phishing database via their REST API.
 *
 * DEMO MODE: When no API key is configured (or key is the placeholder),
 * the class simulates realistic responses based on URL pattern matching.
 * This ensures end-to-end testing without needing a real API key.
 *
 * REAL API KEY SETUP:
 *   1. Register at: https://www.phishtank.com/register.php
 *   2. Get your API key from your account profile
 *   3. Set in config.properties: phishtank.api.key=YOUR_REAL_KEY
 *
 * API docs: https://www.phishtank.com/api_info.php
 */
public final class PhishTankAPI {

    private PhishTankAPI() {}

    private static final String API_URL    = Constants.PHISHTANK_API_URL;
    private static final int    TIMEOUT_MS = 5_000;

    private static String  apiKey   = null;
    private static boolean demoMode = false;

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Loads API key from config.properties and sets demo mode if absent.
     * Must be called once at startup via {@link com.phishguard.detection.ThreatIntelChecker#initialize()}.
     */
    public static void initialize() {
        try {
            apiKey = ConfigLoader.getInstance().get("phishtank.api.key", "");
        } catch (Exception e) {
            apiKey = "";
        }

        if (apiKey == null || apiKey.isBlank()
                || apiKey.toUpperCase().startsWith("YOUR_")) {
            demoMode = true;
            System.out.println("[PhishTank] API key not configured — running in demo mode");
        } else {
            demoMode = false;
            System.out.println("[PhishTank] API key loaded, live mode active");
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Checks whether a URL is listed as a confirmed phishing URL in PhishTank.
     *
     * @param url the URL to check
     * @return true if confirmed phishing, false if safe or on any API error (fail-open)
     */
    public static boolean isPhishing(String url) {
        if (url == null || url.isBlank()) return false;
        if (demoMode) return simulateDemoMode(url);

        try {
            // Build POST body
            String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
            String postData   = "url=" + encodedUrl + "&format=json&app_key=" + apiKey;
            byte[] postBytes  = postData.getBytes(StandardCharsets.UTF_8);

            // Open connection
            URL apiUrl = new URL(API_URL);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("User-Agent",    "phishguard/1.0");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postBytes);
            }

            // Read response
            int    status   = conn.getResponseCode();
            String response = readStream(conn.getInputStream());
            conn.disconnect();

            if (status != 200) {
                System.err.println("[PhishTank] HTTP " + status + " error");
                return false;
            }

            // Parse JSON: look for "in_database": true AND "verified": true
            boolean inDatabase = response.contains("\"in_database\":true")
                              || response.contains("\"in_database\": true");
            boolean verified   = response.contains("\"verified\":true")
                              || response.contains("\"verified\": true");

            boolean result = inDatabase && verified;
            System.out.println("[PhishTank] " + url + " → " + (result ? "PHISHING" : "CLEAN"));
            return result;

        } catch (Exception e) {
            System.err.println("[PhishTank] API error: " + e.getMessage() + " — defaulting to false");
            return false; // fail-open
        }
    }

    /**
     * Returns 1.0 if the URL is confirmed phishing by PhishTank, 0.0 otherwise.
     * Convenience wrapper for use in score pipelines.
     *
     * @param url the URL to check
     * @return 1.0 or 0.0
     */
    public static double getScore(String url) {
        return isPhishing(url) ? 1.0 : 0.0;
    }

    /** @return true if running without a real API key */
    public static boolean isDemoMode() {
        return demoMode;
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Simulates PhishTank response based on URL pattern analysis.
     * Called when no API key is configured. Provides realistic test results.
     *
     * Returns true if the URL contains phishing-indicative words
     * and does NOT appear to be a known-safe domain.
     */
    private static boolean simulateDemoMode(String url) {
        String lower = url.toLowerCase();

        boolean hasSuspiciousKeyword =
            lower.contains("verify")  || lower.contains("login")   ||
            lower.contains("secure")  || lower.contains("account") ||
            lower.contains("update")  || lower.contains("confirm");

        boolean isKnownSafe =
            lower.contains("google")    || lower.contains("microsoft") ||
            lower.contains("apple.com") || lower.contains("amazon.com");

        boolean result = hasSuspiciousKeyword && !isKnownSafe;
        System.out.println("[PhishTank] DEMO MODE — simulated result for: " + url
            + " → " + (result ? "PHISHING" : "CLEAN"));
        return result;
    }

    /** Reads all bytes from an InputStream and returns as UTF-8 string. */
    private static String readStream(InputStream is) throws Exception {
        byte[] buffer = new byte[4096];
        StringBuilder sb = new StringBuilder();
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            sb.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
        }
        return sb.toString();
    }
}
