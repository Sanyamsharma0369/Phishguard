package com.phishguard.email;

import com.phishguard.database.QuarantineDAO;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PhishGuard - URLExtractor.java
 * -------------------------------------------------
 * Extracts all URLs from raw email body text using a regex pattern.
 * De-duplicates results while preserving original order of first appearance.
 *
 * URL regex covers: http:// and https:// URLs with common path characters.
 * Query strings, fragments, and encoded characters are all captured.
 */
public final class URLExtractor {

    // ── Compiled URL regex (compiled once at class load) ─────────────────
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
        Pattern.CASE_INSENSITIVE
    );

    private URLExtractor() {}

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Extracts all URLs from the given text string.
     * Uses regex to find all http/https URLs, de-duplicates preserving order.
     *
     * @param text raw email body or any text block
     * @return ordered list of unique URLs found (empty list if none or null input)
     */
    public static List<String> extract(String text) {
        if (text == null || text.isBlank()) {
            return new ArrayList<>();
        }

        LinkedHashSet<String> seen = new LinkedHashSet<>();
        Matcher matcher = URL_PATTERN.matcher(text);

        while (matcher.find()) {
            String url = matcher.group().trim();
            // Strip trailing punctuation that is not part of the URL
            url = url.replaceAll("[.,;!?)]+$", "");
            seen.add(url);
        }

        return new ArrayList<>(seen);
    }

    /**
     * Extracts URLs from text, then filters out any whose domain
     * is already in the quarantine table.
     *
     * Filtered URLs are logged to console but NOT returned — they
     * should be handled by MitigationEngine as already-known threats.
     *
     * @param text raw email body text
     * @return list of URLs that are NOT quarantined (safe to analyze)
     */
    public static List<String> extractAndFilter(String text) {
        List<String> all = extract(text);
        List<String> filtered = new ArrayList<>();

        for (String url : all) {
            String domain = extractDomain(url);
            try {
                if (!domain.isEmpty() && QuarantineDAO.isDomainQuarantined(domain)) {
                    System.out.println("[URLExtractor] Filtered quarantined URL: " + url);
                    // Don't add to filtered — it's already blocked
                } else {
                    filtered.add(url);
                }
            } catch (Exception e) {
                // Fail-open: if quarantine check throws, include the URL for fresh analysis
                System.err.println("[URLExtractor] Quarantine check failed for " + domain + ": " + e.getMessage());
                filtered.add(url);
            }
        }

        return filtered;
    }

    /**
     * Extracts the registrable domain from a URL string.
     * Strips the "www." prefix for normalisation.
     *
     * Examples:
     *   "http://www.paypal.com/login" → "paypal.com"
     *   "https://evil-site.xyz/path"  → "evil-site.xyz"
     *
     * @param rawUrl full URL string
     * @return clean domain string, or empty string on parse error
     */
    public static String extractDomain(String rawUrl) {
        try {
            String host = new URL(rawUrl).getHost();
            if (host == null) return "";
            // Normalise: strip leading www.
            if (host.toLowerCase().startsWith("www.")) {
                host = host.substring(4);
            }
            return host.toLowerCase();
        } catch (Exception e) {
            // Malformed URL — return empty string, caller handles it
            return "";
        }
    }

    // ── Built-in test suite ───────────────────────────────────────────────

    /**
     * Runs 3 test cases and prints pass/fail for each.
     * Call from Main.java to verify behaviour during development.
     */
    public static void testAll() {
        System.out.println("[URLExtractor] ─────────────────────────────────────");

        // Test 1: two URLs in normal text
        String t1 = "Click here: http://paypal-verify.xyz/login and https://google.com for help";
        List<String> r1 = extract(t1);
        boolean pass1 = r1.size() == 2;
        System.out.println("[URLExtractor] Test 1: Found " + r1.size() + " URLs "
            + (pass1 ? "✓ PASS" : "✗ FAIL") + " → " + r1);

        // Test 2: null input — must not throw
        List<String> r2 = extract(null);
        boolean pass2 = r2.isEmpty();
        System.out.println("[URLExtractor] Test 2: null input → " + r2.size() + " URLs "
            + (pass2 ? "✓ PASS" : "✗ FAIL"));

        // Test 3: text with no URLs
        List<String> r3 = extract("no urls here at all");
        boolean pass3 = r3.isEmpty();
        System.out.println("[URLExtractor] Test 3: no URLs → " + r3.size() + " URLs "
            + (pass3 ? "✓ PASS" : "✗ FAIL"));

        // Bonus test 4: duplicate URL deduplication
        String t4 = "http://evil.com http://evil.com https://legit.com";
        List<String> r4 = extract(t4);
        boolean pass4 = r4.size() == 2; // deduped evil.com appears once
        System.out.println("[URLExtractor] Test 4: dedup → " + r4.size() + " URLs "
            + (pass4 ? "✓ PASS" : "✗ FAIL") + " → " + r4);

        System.out.println("[URLExtractor] ─────────────────────────────────────");
    }
}
