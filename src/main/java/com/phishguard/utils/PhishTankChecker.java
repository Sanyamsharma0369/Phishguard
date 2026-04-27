package com.phishguard.utils;

import com.phishguard.utils.ThreatIntelCache.CacheResult;
import java.net.*;
import java.net.http.*;
import java.util.Optional;

public class PhishTankChecker {

    private static final String API_KEY = System.getenv()
        .getOrDefault("PT_API_KEY", "");
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public record PTResult(boolean isPhishing, boolean verified, boolean fromCache) {}

    public static PTResult check(String url) {
        // ── 1. Cache Hit ──────────────────────────────────────────────────────
        Optional<CacheResult> cached = ThreatIntelCache.get(url);
        if (cached.isPresent() && 
            (cached.get().source().contains("PT") || cached.get().source().equals("NONE"))) {
            CacheResult c = cached.get();
            System.out.println("[PT] Cache hit for: " + url.substring(0, Math.min(60, url.length())));
            return new PTResult(c.ptIsPhishing(), c.ptVerified(), true);
        }

        // ── 2. Live API Call ──────────────────────────────────────────────────
        try {
            String body = "url=" + URLEncoder.encode(url, "UTF-8")
                + "&format=json"
                + (API_KEY.isBlank() ? "" : "&app_key=" + API_KEY);

            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://checkurl.phishtank.com/checkurl/"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "phishguard-detector/1.0")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

            HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() == 200) {
                var json = com.google.gson.JsonParser.parseString(res.body())
                    .getAsJsonObject();
                var results = json.getAsJsonObject("results");
                boolean isPhishing = results.get("in_database").getAsBoolean()
                                  && results.get("valid").getAsBoolean();
                boolean verified = isPhishing
                    && results.has("verified")
                    && results.get("verified").getAsBoolean();

                // ── Cache the result ──────────────────────────────────────────
                double vtScore = 0.0;
                int vtPos = 0, vtTotal = 0;
                String source = "PT";
                if (cached.isPresent()) {
                    vtScore = cached.get().vtScore();
                    vtPos = cached.get().vtPositives();
                    vtTotal = cached.get().vtTotal();
                    source = "BOTH";
                }
                ThreatIntelCache.put(url, vtScore, vtPos, vtTotal, isPhishing, verified, source);

                System.out.printf("[PT] Live check: phishing=%b verified=%b → cached%n",
                    isPhishing, verified);
                return new PTResult(isPhishing, verified, false);
            }

        } catch (Exception e) {
            System.err.println("[PT] Error: " + e.getMessage());
        }

        ThreatIntelCache.put(url, 0.0, 0, 0, false, false, "NONE");
        return new PTResult(false, false, false);
    }
}
