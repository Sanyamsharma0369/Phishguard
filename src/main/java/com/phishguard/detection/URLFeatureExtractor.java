package com.phishguard.detection;

import com.phishguard.utils.Constants;
import com.phishguard.utils.EntropyCalculator;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * PhishGuard - URLFeatureExtractor.java
 * -------------------------------------------------
 * Converts any URL string into an 8-element double[] feature vector
 * suitable for input into the Weka ML models.
 *
 * FEATURE VECTOR (index → name → description):
 *  [0] url_length          — normalized URL length (÷200)
 *  [1] has_https           — 1.0 if HTTPS, 0.0 if HTTP or other
 *  [2] has_ip_address      — 1.0 if host is an IP address
 *  [3] suspicious_keyword_count — normalized count of phishing keywords (÷10)
 *  [4] dot_count           — normalized '.' count in full URL (÷10)
 *  [5] special_char_count  — normalized count of @, -, _, %, =, & (÷20)
 *  [6] entropy             — Shannon entropy of the URL (0.0–5.2)
 *  [7] subdomain_count     — normalized subdomain depth (÷5)
 *
 * All normalized values are clamped to [0.0, 1.0].
 * Entropy is kept raw (Weka handles the scale).
 *
 * Keywords are loaded ONCE at class load from resources/keywords.txt.
 */
public final class URLFeatureExtractor {

    // ── Regex: IPv4 address in host ─────────────────────────────────────
    private static final Pattern IP_PATTERN =
        Pattern.compile("\\b(\\d{1,3}\\.){3}\\d{1,3}\\b");

    // ── Loaded phishing keywords ────────────────────────────────────────
    private static final List<String> KEYWORDS = new ArrayList<>();

    // ── Static initializer: load keywords once ──────────────────────────
    static {
        loadKeywords();
    }

    private URLFeatureExtractor() {}

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Extracts and normalizes 8 features from the given URL.
     *
     * @param url raw URL string (e.g., "http://paypal-secure.xyz/login")
     * @return double[8] feature vector, all zeros if url is null/empty
     */
    public static double[] extract(String url) {
        double[] features = new double[Constants.FEATURE_COUNT];  // defaults to 0.0

        if (url == null || url.isBlank()) {
            System.err.println("[URLFeature] Warning: null or empty URL supplied.");
            return features;
        }

        try {
            String normalizedUrl = url.trim();

            // Parse to extract host
            String host = extractHost(normalizedUrl);

            // ── Feature [0]: URL Length (normalized ÷ 200) ──────────────
            features[Constants.FEAT_URL_LENGTH] =
                Math.min(1.0, normalizedUrl.length() / 200.0);

            // ── Feature [1]: Has HTTPS ───────────────────────────────────
            features[Constants.FEAT_HAS_HTTPS] =
                normalizedUrl.toLowerCase().startsWith("https://") ? 1.0 : 0.0;

            // ── Feature [2]: Has IP Address ──────────────────────────────
            features[Constants.FEAT_HAS_IP] =
                (host != null && IP_PATTERN.matcher(host).find()) ? 1.0 : 0.0;

            // ── Feature [3]: Suspicious Keyword Count (normalized ÷ 10) ──
            features[Constants.FEAT_KEYWORD_COUNT] =
                Math.min(1.0, countKeywords(normalizedUrl) / 10.0);

            // ── Feature [4]: Dot Count (normalized ÷ 10) ─────────────────
            features[Constants.FEAT_DOT_COUNT] =
                Math.min(1.0, countChar(normalizedUrl, '.') / 10.0);

            // ── Feature [5]: Special Char Count (normalized ÷ 20) ─────────
            features[Constants.FEAT_SPECIAL_CHARS] =
                Math.min(1.0, countSpecialChars(normalizedUrl) / 20.0);

            // ── Feature [6]: Shannon Entropy (kept raw) ───────────────────
            features[Constants.FEAT_ENTROPY] =
                EntropyCalculator.calculate(normalizedUrl);

            // ── Feature [7]: Subdomain Count (normalized ÷ 5) ────────────
            features[Constants.FEAT_SUBDOMAIN_COUNT] =
                Math.min(1.0, countSubdomains(host) / 5.0);

        } catch (Exception e) {
            System.err.println("[URLFeature] Error extracting features from URL '" + url + "': " + e.getMessage());
            // Return partial results (whatever was computed before the exception)
        }

        return features;
    }

    // ── Private feature helpers ─────────────────────────────────────────

    /**
     * Extracts the host portion from a URL string.
     * Returns null if the URL is malformed.
     */
    private static String extractHost(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception e) {
            // Fallback: manually extract between // and the next /
            try {
                int start = url.indexOf("//");
                if (start == -1) return url;
                start += 2;
                int end = url.indexOf("/", start);
                return (end == -1) ? url.substring(start) : url.substring(start, end);
            } catch (Exception ignored) {
                return null;
            }
        }
    }

    /**
     * Counts occurrences of phishing keywords in the URL path + host.
     * Uses the keywords loaded from resources/keywords.txt.
     * Case-insensitive matching.
     *
     * @param url full URL string
     * @return count of matched keywords
     */
    private static int countKeywords(String url) {
        if (KEYWORDS.isEmpty()) return 0;
        String lowerUrl = url.toLowerCase();
        int count = 0;
        for (String keyword : KEYWORDS) {
            if (lowerUrl.contains(keyword)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Counts how many levels of subdomain exist in the host.
     * Example: "a.b.example.com" → 2 subdomains (a, b)
     * "www.example.com" → 1 subdomain (www)
     * "example.com" → 0 subdomains
     *
     * We simply count dots - 1 (for the TLD dot).
     * Special handling for common TLDs like .co.uk, .com.au.
     *
     * @param host the host string from the URL, or null
     * @return number of subdomain levels
     */
    private static int countSubdomains(String host) {
        if (host == null || host.isBlank()) return 0;

        // Strip trailing dot if present
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        String[] parts = host.split("\\.");
        // e.g., "a.b.example.com" → ["a","b","example","com"] → 4 parts
        // subdomains = total parts - 2 (registrable domain + TLD)
        int subdomains = parts.length - 2;
        return Math.max(0, subdomains);
    }

    /**
     * Counts occurrences of phishing-relevant special characters in the URL.
     * Characters checked: @, -, _, %, =, &
     *
     * @param url full URL string
     * @return count of special characters
     */
    private static int countSpecialChars(String url) {
        int count = 0;
        for (char c : url.toCharArray()) {
            if (c == '@' || c == '-' || c == '_' ||
                c == '%' || c == '=' || c == '&') {
                count++;
            }
        }
        return count;
    }

    /**
     * Counts occurrences of a specific character in a string.
     *
     * @param s    source string
     * @param target character to count
     * @return number of occurrences
     */
    private static int countChar(String s, char target) {
        int count = 0;
        for (char c : s.toCharArray()) {
            if (c == target) count++;
        }
        return count;
    }

    /**
     * Loads phishing keywords from classpath resources/keywords.txt.
     * Called once via static initializer block.
     * All comments (lines starting with #) and blank lines are ignored.
     */
    private static void loadKeywords() {
        try (InputStream is = URLFeatureExtractor.class.getResourceAsStream(Constants.KEYWORDS_FILE)) {
            if (is == null) {
                System.err.println("[URLFeature] Warning: keywords.txt not found on classpath. Keyword scoring disabled.");
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (!line.isBlank() && !line.startsWith("#")) {
                        KEYWORDS.add(line);
                    }
                }
            }
            System.out.println("[URLFeature] Loaded " + KEYWORDS.size() + " phishing keywords from keywords.txt");
        } catch (Exception e) {
            System.err.println("[URLFeature] Error loading keywords.txt: " + e.getMessage());
        }
    }

    // ── Built-in test suite ─────────────────────────────────────────────

    /**
     * Tests feature extraction on 3 representative URLs.
     * Prints a formatted table for manual verification.
     * Call from Main.java during development.
     */
    public static void testAll() {
        System.out.println("[URLFeatureTest] ─────────────────────────────────────────────────────");

        String[] testUrls = {
            "http://192.168.1.1/paypal/login/verify-account/confirm",           // Phishing (IP + no HTTPS)
            "https://www.google.com",                                            // Legitimate
            "http://paypal-secure-verify-login.xyz/account/update"              // Suspicious
        };
        String[] labels = {"PHISHING", "LEGITIMATE", "SUSPICIOUS"};

        for (int i = 0; i < testUrls.length; i++) {
            double[] f = extract(testUrls[i]);
            System.out.printf("[URLFeatureTest] %-10s → [len=%.2f, https=%.0f, ip=%.0f, kw=%.2f, dots=%.2f, spec=%.2f, ent=%.2f, sub=%.2f]%n",
                labels[i], f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
        }

        System.out.println("[URLFeatureTest] ─────────────────────────────────────────────────────");
    }
}
