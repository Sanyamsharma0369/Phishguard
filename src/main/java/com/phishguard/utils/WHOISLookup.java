package com.phishguard.utils;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;

/**
 * PhishGuard - WHOISLookup.java
 * -------------------------------------------------
 * Checks domain registration age via the free WHOIS JSON API.
 *
 * API used: https://api.whoisjsonapi.com/v1/{domain}
 * Free tier, no API key required for basic lookups.
 *
 * Rationale: Phishing domains are typically registered days (not years)
 * before use. A domain younger than 30 days is flagged as suspicious.
 *
 * Fail-safe design: If the lookup fails for any reason (network timeout,
 * invalid domain, API limit), returns 999 (treated as "old/safe domain")
 * to avoid false positives from connectivity issues.
 */
public final class WHOISLookup {

    // Endpoint template
    private static final String API_URL = "https://api.whoisjsonapi.com/v1/%s";

    // Date formats the API may return
    private static final DateTimeFormatter[] DATE_FORMATS = {
        DateTimeFormatter.ofPattern("yyyy-MM-dd"),
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssX"),
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"),
        DateTimeFormatter.ofPattern("dd-MMM-yyyy"),
        DateTimeFormatter.ofPattern("yyyyMMdd"),
    };

    private WHOISLookup() {}

    /**
     * Returns the age of the given domain in days.
     *
     * @param domain the domain to look up, e.g., "paypal-secure.xyz"
     *               (pass only the registrable domain, not a full URL)
     * @return days since domain creation, or 999 if lookup fails/times out
     */
    public static int getDomainAgeDays(String domain) {
        if (domain == null || domain.isBlank()) {
            System.err.println("[WHOIS] Warning: null or blank domain supplied.");
            return 999;
        }

        // Strip leading www. if present
        String cleanDomain = domain.toLowerCase().trim();
        if (cleanDomain.startsWith("www.")) {
            cleanDomain = cleanDomain.substring(4);
        }

        try {
            String jsonResponse = fetchWhoisJson(cleanDomain);
            if (jsonResponse == null || jsonResponse.isBlank()) {
                System.out.println("[WHOIS] Empty response for domain: " + cleanDomain);
                return 999;
            }

            // Parse the JSON and extract creation date
            String createdDate = extractCreatedDate(jsonResponse);
            if (createdDate == null) {
                System.out.println("[WHOIS] Could not find creation date for: " + cleanDomain);
                return 999;
            }

            int days = calculateDaysSince(createdDate);
            System.out.printf("[WHOIS] Domain '%s' created: %s (%d days ago)%n",
                cleanDomain, createdDate, days);
            return days;

        } catch (Exception e) {
            // Silent fail — network issues should not cause false positives
            System.out.println("[WHOIS] Lookup failed for '" + cleanDomain + "': " + e.getMessage());
            return 999;
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /**
     * Performs the HTTP GET request to the WHOIS API.
     *
     * @param domain clean domain name
     * @return raw JSON string response, or null on failure
     * @throws Exception on network or IO error
     */
    private static String fetchWhoisJson(String domain) throws Exception {
        String urlStr = String.format(API_URL, domain);
        URL url = URI.create(urlStr).toURL();

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(Constants.HTTP_CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(Constants.HTTP_READ_TIMEOUT_MS);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("User-Agent", "PhishGuard/1.0");

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            System.out.println("[WHOIS] HTTP " + responseCode + " for domain: " + domain);
            return null;
        }

        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }

        return sb.toString();
    }

    /**
     * Extracts the "created_date" (or similar) field from the WHOIS JSON response.
     * Tries multiple common field names from different WHOIS providers.
     *
     * @param json raw JSON response string
     * @return date string, or null if not found
     */
    private static String extractCreatedDate(String json) {
        try {
            JSONObject root = new JSONObject(json);

            // Common field names across WHOIS APIs
            String[] fieldNames = {
                "created_date", "creation_date", "createdDate",
                "registered", "registrationDate", "created"
            };

            for (String field : fieldNames) {
                if (root.has(field) && !root.isNull(field)) {
                    String val = root.getString(field);
                    if (val != null && !val.isBlank()) {
                        return val;
                    }
                }
            }

            // Some APIs nest it under a "result" or "data" sub-object
            if (root.has("result")) {
                return extractCreatedDate(root.getJSONObject("result").toString());
            }
            if (root.has("domain")) {
                JSONObject domainObj = root.getJSONObject("domain");
                if (domainObj.has("created_date")) {
                    return domainObj.getString("created_date");
                }
            }

        } catch (Exception e) {
            System.out.println("[WHOIS] JSON parsing error: " + e.getMessage());
        }

        return null;
    }

    /**
     * Parses a date string using multiple possible formats and returns
     * the number of days since that date.
     *
     * @param dateStr raw date string from WHOIS API
     * @return days since the date, or 999 if parsing fails
     */
    private static int calculateDaysSince(String dateStr) {
        // Strip time portion if it's a full datetime string
        String datePart = dateStr.trim().split("T")[0].split(" ")[0];

        for (DateTimeFormatter fmt : DATE_FORMATS) {
            try {
                LocalDate created = LocalDate.parse(datePart, fmt);
                LocalDate today = LocalDate.now();
                return (int) ChronoUnit.DAYS.between(created, today);
            } catch (DateTimeParseException ignored) {
                // Try next format
            }
        }

        System.out.println("[WHOIS] Could not parse date string: '" + dateStr + "'");
        return 999;
    }

    /**
     * Convenience: returns true if domain is younger than the configured threshold.
     *
     * @param domain domain to check
     * @return true if domain age < Constants.WHOIS_MIN_DOMAIN_AGE_DAYS
     */
    public static boolean isNewDomain(String domain) {
        int ageDays = getDomainAgeDays(domain);
        return ageDays < Constants.WHOIS_MIN_DOMAIN_AGE_DAYS;
    }
}
