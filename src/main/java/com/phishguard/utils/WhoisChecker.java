package com.phishguard.utils;

import java.net.*;
import java.net.http.*;
import java.time.*;
import java.time.format.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.*;

/**
 * WhoisChecker — checks domain age using RDAP and WHOIS APIs.
 * Phishing domains are often extremely new (< 30 days).
 */
public class WhoisChecker {

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    public record WhoisResult(
        int ageDays,           // -1 = unknown
        boolean isNewDomain,   // true if < 30 days
        boolean isVeryNew,     // true if < 7 days
        double riskBonus,      // amount to add to risk score
        String ageLabel,       // "3 days", "2 months", "5 years"
        String registeredDate, // human readable
        boolean fromCache
    ) {}

    // ── In-memory cache (domain → result) ───────────────────────────────────
    private static final Map<String, WhoisResult> memCache = 
        Collections.synchronizedMap(new LinkedHashMap<>() {
            protected boolean removeEldestEntry(Map.Entry<String,WhoisResult> e) {
                return size() > 500; // Keep max 500 domains
            }
        });

    public static WhoisResult check(String url) {
        String domain = extractDomain(url);
        if (domain == null || domain.isBlank()) {
            return unknown();
        }

        // ── Cache check ───────────────────────────────────────────────────────
        if (memCache.containsKey(domain)) {
            System.out.println("[WHOIS] Cache hit: " + domain);
            WhoisResult cached = memCache.get(domain);
            return new WhoisResult(cached.ageDays(), cached.isNewDomain(),
                cached.isVeryNew(), cached.riskBonus(), cached.ageLabel(),
                cached.registeredDate(), true);
        }

        // ── Method 1: RDAP (free, no key needed) ─────────────────────────────
        WhoisResult result = tryRdap(domain);

        // ── Method 2: Fallback to WHOIS API ──────────────────────────────────
        if (result == null) result = tryWhoisApi(domain);

        // ── Method 3: Unknown fallback ────────────────────────────────────────
        if (result == null) result = unknown();

        memCache.put(domain, result);
        System.out.printf("[WHOIS] %s → %s (risk bonus: +%.2f)%n",
            domain, result.ageLabel(), result.riskBonus());
        return result;
    }

    // ── RDAP — completely free, no API key needed ────────────────────────────
    private static WhoisResult tryRdap(String domain) {
        try {
            String rdapUrl = "https://rdap.org/domain/" + domain;
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(rdapUrl))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(5))
                .GET().build();

            HttpResponse<String> res = HTTP.send(req, 
                HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() == 200) {
                // Parse registration date from RDAP response
                Pattern p = Pattern.compile(
                    "\"registration\"\\s*:\\s*\"([^\"]+)\"");
                Matcher m = p.matcher(res.body());

                // Also try "registrationDate" and "created"
                if (!m.find()) {
                    p = Pattern.compile("\"registrationDate\"\\s*:\\s*\"([^\"]+)\"");
                    m = p.matcher(res.body());
                }

                if (m.find()) {
                    String dateStr = m.group(1);
                    return parseAndBuild(dateStr, domain);
                }
            }
        } catch (Exception e) {
            System.err.println("[WHOIS] RDAP failed for " + domain + 
                               ": " + e.getMessage());
        }
        return null;
    }

    // ── Fallback: whoisjson.com (free tier, no key) ──────────────────────────
    private static WhoisResult tryWhoisApi(String domain) {
        try {
            String apiUrl = "https://whoisjson.com/api/v1/whois?domain=" + domain;
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(5))
                .GET().build();

            HttpResponse<String> res = HTTP.send(req, 
                HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() == 200) {
                Pattern p = Pattern.compile(
                    "\"created\"\\s*:\\s*\"([^\"]+)\"");
                Matcher m = p.matcher(res.body());
                if (m.find()) {
                    return parseAndBuild(m.group(1), domain);
                }
            }
        } catch (Exception e) {
            System.err.println("[WHOIS] API fallback failed: " + e.getMessage());
        }
        return null;
    }

    // ── Parse date string and build result ───────────────────────────────────
    private static WhoisResult parseAndBuild(String dateStr, String domain) {
        try {
            LocalDate created = null;

            // Try multiple date formats
            List<DateTimeFormatter> formats = List.of(
                DateTimeFormatter.ISO_DATE_TIME,
                DateTimeFormatter.ISO_OFFSET_DATE_TIME,
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
                DateTimeFormatter.ofPattern("yyyy-MM-dd")
            );

            for (DateTimeFormatter fmt : formats) {
                try {
                    created = LocalDate.parse(dateStr.substring(0, 
                        Math.min(dateStr.length(), 19)), fmt);
                    break;
                } catch (Exception ignored) {}
            }

            if (created == null) return null;

            long ageDays = ChronoUnit.DAYS.between(created, LocalDate.now());
            String ageLabel = formatAge(ageDays);
            String registeredDate = created.format(
                DateTimeFormatter.ofPattern("dd MMM yyyy"));

            boolean isVeryNew  = ageDays < 7;
            boolean isNewDomain = ageDays < 30;

            // Risk bonus calculation
            double riskBonus;
            if      (ageDays < 7)   riskBonus = 0.35;
            else if (ageDays < 30)  riskBonus = 0.25;
            else if (ageDays < 90)  riskBonus = 0.10;
            else if (ageDays < 365) riskBonus = 0.05;
            else                    riskBonus = -0.05; // Trust bonus for old domains

            return new WhoisResult((int) ageDays, isNewDomain, isVeryNew,
                riskBonus, ageLabel, registeredDate, false);

        } catch (Exception e) {
            System.err.println("[WHOIS] Parse error: " + e.getMessage());
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    public static String extractDomain(String url) {
        try {
            String host = new URL(url).getHost();
            // Remove www.
            if (host.startsWith("www.")) host = host.substring(4);
            // Get root domain (e.g. paypal-secure.com from sub.paypal-secure.com)
            String[] parts = host.split("\\.");
            if (parts.length >= 2) {
                return parts[parts.length - 2] + "." + parts[parts.length - 1];
            }
            return host;
        } catch (Exception e) {
            return null;
        }
    }

    private static String formatAge(long days) {
        if (days < 1)   return "Less than 1 day";
        if (days < 7)   return days + " day" + (days == 1 ? "" : "s");
        if (days < 30)  return (days / 7) + " week" + (days/7 == 1 ? "" : "s");
        if (days < 365) return (days / 30) + " month" + (days/30 == 1 ? "" : "s");
        long years = days / 365;
        return years + " year" + (years == 1 ? "" : "s");
    }

    private static WhoisResult unknown() {
        return new WhoisResult(-1, false, false, 0.0, "Unknown", "Unknown", false);
    }

    public static void clearCache() {
        memCache.clear();
    }
}
