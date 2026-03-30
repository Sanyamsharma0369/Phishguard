package com.phishguard.utils;

/**
 * PhishGuard - EntropyCalculator.java
 * -------------------------------------------------
 * Calculates Shannon entropy of a string (typically a URL).
 *
 * Entropy measures how random/obfuscated a URL looks.
 * Formula: H = -Σ [ p(c) × log₂(p(c)) ]
 * where p(c) = frequency of character c / total length
 *
 * Interpretation:
 *   Low entropy  (< 2.5) → regular English text, likely legitimate
 *   Medium entropy (2.5–3.5) → borderline
 *   High entropy  (> 3.5) → random/encoded = phishing indicator
 *
 * Example:
 *   "aaaa"          → entropy ≈ 0.0 (all same char)
 *   "abcdefghijkl"  → entropy ≈ 3.58 (all unique)
 *   URL with hex encoding → often > 4.0
 */
public final class EntropyCalculator {

    private EntropyCalculator() {}

    /**
     * Computes Shannon entropy of the given text.
     *
     * @param text any string (URL, domain, email body snippet, etc.)
     * @return entropy value in bits (0.0 to ~5.2 for typical ASCII text)
     *         Returns 0.0 for null or empty strings.
     */
    public static double calculate(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }

        int length = text.length();

        // ── Build frequency map using ASCII or Unicode code points ──
        // We use an int array for speed over a HashMap for ASCII (0–127)
        // and fall back to a HashMap for any extended chars.
        int[] freq = new int[256];
        int extendedCount = 0;
        java.util.Map<Character, Integer> extFreq = null;

        for (char c : text.toCharArray()) {
            if (c < 256) {
                freq[c]++;
            } else {
                extendedCount++;
                if (extFreq == null) extFreq = new java.util.HashMap<>();
                extFreq.merge(c, 1, Integer::sum);
            }
        }

        // ── Compute entropy ──
        double entropy = 0.0;

        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / length;
                entropy -= p * (Math.log(p) / Math.log(2)); // log₂(p) = ln(p)/ln(2)
            }
        }

        // Handle extended characters if any
        if (extFreq != null) {
            for (int count : extFreq.values()) {
                if (count > 0) {
                    double p = (double) count / length;
                    entropy -= p * (Math.log(p) / Math.log(2));
                }
            }
        }

        // Round to 4 decimal places for clean output
        return Math.round(entropy * 10000.0) / 10000.0;
    }

    /**
     * Convenience method: returns true if entropy exceeds the configured threshold.
     * A high-entropy URL is suspicious (likely obfuscated or randomly generated).
     *
     * @param text string to evaluate
     * @return true if entropy > Constants.HIGH_ENTROPY_THRESHOLD (3.5)
     */
    public static boolean isHighEntropy(String text) {
        return calculate(text) > Constants.HIGH_ENTROPY_THRESHOLD;
    }

    // ── Built-in test suite ─────────────────────────────────────────────

    /**
     * Runs 3 inline test cases and prints results.
     * Call this from Main.java during development to verify correctness.
     */
    public static void testAll() {
        System.out.println("[EntropyTest] ─────────────────────────────────────────");

        // Test 1: Trivial — all same characters, entropy = 0
        String t1 = "aaaa";
        double e1 = calculate(t1);
        System.out.printf("[EntropyTest] '%s' → %.4f (expected ~0.0) %s%n",
            t1, e1, e1 < 0.01 ? "✓ PASS" : "✗ FAIL");

        // Test 2: Legitimate URL — should be low-medium entropy
        String t2 = "https://www.google.com/search?q=java";
        double e2 = calculate(t2);
        System.out.printf("[EntropyTest] '%s' → %.4f (expected 2.5–4.0) %s%n",
            t2, e2, (e2 >= 2.5 && e2 <= 4.5) ? "✓ PASS" : "✗ FAIL");

        // Test 3: Obfuscated phishing URL — should be high entropy
        String t3 = "http://xn--pypal-4ve.com/cgi-bin/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d7b9b";
        double e3 = calculate(t3);
        System.out.printf("[EntropyTest] (phishing url) → %.4f (expected > 3.5) %s%n",
            e3, e3 > 3.5 ? "✓ PASS" : "✗ FAIL");

        System.out.println("[EntropyTest] ─────────────────────────────────────────");
    }
}
