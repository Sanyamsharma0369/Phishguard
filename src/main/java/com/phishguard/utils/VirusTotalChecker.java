package com.phishguard.utils;

import com.google.gson.*;
import com.phishguard.utils.ThreatIntelCache.CacheResult;
import java.net.*;
import java.net.http.*;
import java.util.Base64;
import java.util.Optional;

public class VirusTotalChecker {

    private static final String API_KEY = System.getenv()
        .getOrDefault("VT_API_KEY", "YOUR_VT_API_KEY_HERE");
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public static String getApiKey() {
        return API_KEY;
    }

    public record VTResult(double score, int positives, int total, boolean fromCache) {}

    public static VTResult check(String url) {
        // ── 1. Cache Hit ──────────────────────────────────────────────────────
        Optional<CacheResult> cached = ThreatIntelCache.get(url);
        if (cached.isPresent() && 
            (cached.get().source().contains("VT") || cached.get().source().equals("NONE"))) {
            CacheResult c = cached.get();
            System.out.println("[VT] Cache hit for: " + url.substring(0, Math.min(60, url.length())));
            return new VTResult(c.vtScore(), c.vtPositives(), c.vtTotal(), true);
        }

        // ── 2. API Key guard ──────────────────────────────────────────────────
        if (API_KEY.equals("YOUR_VT_API_KEY_HERE") || API_KEY.isBlank()) {
            System.out.println("[VT] No API key configured — skipping.");
            cacheNoneResult(url);
            return new VTResult(0.0, 0, 0, false);
        }

        // ── 3. Live API Call ──────────────────────────────────────────────────
        try {
            String urlId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.getBytes()).replaceAll("=", "");

            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/urls/" + urlId))
                .header("x-apikey", API_KEY)
                .GET()
                .build();

            HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() == 200) {
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                JsonObject stats = json.getAsJsonObject("data")
                    .getAsJsonObject("attributes")
                    .getAsJsonObject("last_analysis_stats");

                int positives = stats.get("malicious").getAsInt()
                              + stats.get("suspicious").getAsInt();
                int total = positives
                          + stats.get("harmless").getAsInt()
                          + stats.get("undetected").getAsInt();
                double score = total > 0 ? (double) positives / total : 0.0;

                // ── Cache the result ──────────────────────────────────────────
                // Get existing PT data if present
                double ptIsPhishing = 0;
                boolean ptVerified = false;
                String source = "VT";
                if (cached.isPresent()) {
                    ptIsPhishing = cached.get().ptIsPhishing() ? 1 : 0;
                    ptVerified = cached.get().ptVerified();
                    source = "BOTH";
                }
                ThreatIntelCache.put(url, score, positives, total,
                    (int) ptIsPhishing == 1, ptVerified, source);

                System.out.printf("[VT] Live scan: %d/%d malicious (%.3f) → cached%n",
                    positives, total, score);
                return new VTResult(score, positives, total, false);

            } else if (res.statusCode() == 404) {
                // URL not in VT yet — submit it
                System.out.println("[VT] URL not found (404) — submitting for scan.");
                submitUrl(url);
                cacheNoneResult(url);
                return new VTResult(0.0, 0, 0, false);

            } else if (res.statusCode() == 429) {
                System.out.println("[VT] Rate limited (429) — using cached/default.");
                cacheNoneResult(url);
                return new VTResult(0.0, 0, 0, false);
            }

        } catch (Exception e) {
            System.err.println("[VT] Error: " + e.getMessage());
        }

        cacheNoneResult(url);
        return new VTResult(0.0, 0, 0, false);
    }

    private static void submitUrl(String url) {
        try {
            String body = "url=" + URLEncoder.encode(url, "UTF-8");
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
                .header("x-apikey", API_KEY)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            System.err.println("[VT] Submit error: " + e.getMessage());
        }
    }

    private static void cacheNoneResult(String url) {
        ThreatIntelCache.put(url, 0.0, 0, 0, false, false, "NONE");
    }
}
