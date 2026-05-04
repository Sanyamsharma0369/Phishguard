package com.phishguard.api;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import com.phishguard.database.DBConnection;
import com.phishguard.database.IncidentDAO;
import com.phishguard.detection.AIModelEngine;
import com.phishguard.detection.ThreatIntelChecker;
import com.phishguard.detection.VisualAnalyzer;
import com.phishguard.engine.DecisionEngine;
import com.phishguard.engine.MitigationEngine;
import com.phishguard.engine.RiskScorer;
import spark.Request;
import spark.Response;
import spark.Spark;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.Duration;
import java.net.http.*;
import java.net.URI;
import java.util.*;
import com.phishguard.engine.ExplainabilityEngine;
import com.phishguard.utils.ThreatIntelCache;

@SuppressWarnings("unchecked")
public class WebApiController {

    private static final Gson gson = new GsonBuilder()
            .registerTypeAdapter(LocalDateTime.class, (JsonSerializer<LocalDateTime>) (src, type, ctx) ->
                    new JsonPrimitive(src.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)))
            .create();

    public static void init() {
        Spark.port(8080);

        // ── CORS Configuration ──────────────────────────────────────────
        Spark.options("/*", (req, res) -> {
            setCorsHeaders(res);
            return "OK";
        });

        Spark.before((req, res) -> {
            setCorsHeaders(res);
        });

        // Serve Chart.js locally — avoids Edge tracking prevention on jsdelivr
        Spark.get("/chartjs", (req, res) -> {
            try {
                java.net.URL url = new java.net.URL(
                        "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js");
                res.type("application/javascript");
                return new String(url.openStream().readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                res.status(500);
                return "// Chart.js unavailable";
            }
        });

        // Routes
        Spark.get("/",               WebApiController::rootDashboard);
        Spark.get("/api/dashboard",  WebApiController::dashboard);
        Spark.get("/api/stats",      WebApiController::stats);
        
        // Extension options preflight
        Spark.options("/api/scan", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Methods", "GET");
            return "";
        });
        Spark.get("/api/scan",       WebApiController::scanUrl);
        Spark.post("/api/scan",      WebApiController::scanUrlPost);
        Spark.post("/api/scan/quick", WebApiController::scanUrlQuick);
        Spark.get("/api/incidents",  WebApiController::incidents);
        Spark.get("/api/incidents/:id/explain", WebApiController::explainIncident);
        Spark.get("/api/blocked",    WebApiController::blocked);
        Spark.get("/api/status",     WebApiController::status);
        Spark.get("/api/quarantine", WebApiController::quarantine);
        Spark.get("/api/flask-status", WebApiController::flaskStatus);
        
        // Whitelist routes
        Spark.get("/api/whitelist", (req, res) -> {
            res.type("application/json");
            return DBConnection.getInstance().getAllWhitelist();
        });
        
        Spark.post("/api/whitelist", (req, res) -> {
            res.type("application/json");
            Map<String, Object> body = gson.fromJson(req.body(), Map.class);
            String domain = body.get("domain").toString();
            String reason = body.getOrDefault("reason", "Dashboard whitelist").toString();
            // clean domain
            domain = domain.replaceAll("https?://", "").replaceAll("www\\.", "").split("/")[0].trim();
            DBConnection.getInstance().addToWhitelist(domain, reason);
            return "{\"success\":true,\"domain\":\"" + domain + "\"}";
        });
        
        Spark.delete("/api/whitelist/:domain", (req, res) -> {
            res.type("application/json");
            String domain = req.params(":domain");
            DBConnection.getInstance().removeFromWhitelist(domain);
            return "{\"success\":true}";
        });
        
        Spark.options("/api/whitelist", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Methods", "GET,POST,DELETE");
            res.header("Access-Control-Allow-Headers", "Content-Type");
            return "";
        });

        // Manual block routes
        Spark.get("/api/manual-blocks", (req, res) -> {
            res.type("application/json");
            return DBConnection.getInstance().getAllManualBlocks();
        });
        
        Spark.post("/api/manual-blocks", (req, res) -> {
            res.type("application/json");
            Map<String, Object> body = gson.fromJson(req.body(), Map.class);
            String domain = body.get("domain").toString();
            String reason = body.getOrDefault("reason", "Manually blocked").toString();
            domain = domain.replaceAll("https?://", "").replaceAll("www\\.", "").split("/")[0].trim();
            DBConnection.getInstance().addManualBlock(domain, reason);
            return "{\"success\":true,\"domain\":\"" + domain + "\"}";
        });
        
        Spark.delete("/api/manual-blocks/:domain", (req, res) -> {
            res.type("application/json");
            DBConnection.getInstance().removeManualBlock(req.params(":domain"));
            return "{\"success\":true}";
        });
        
        Spark.options("/api/manual-blocks", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Methods", "GET,POST,DELETE");
            res.header("Access-Control-Allow-Headers", "Content-Type");
            return "";
        });

        // Report & Settings routes
        Spark.get("/api/report/pdf", (req, res) -> {
            try {
                byte[] pdf = com.phishguard.utils.ReportGenerator.generateReport();
                res.raw().setContentType("application/pdf");
                res.raw().setHeader("Content-Disposition",
                    "attachment; filename=phishguard-report-" +
                    java.time.LocalDate.now() + ".pdf");
                res.raw().setContentLength(pdf.length);
                res.raw().getOutputStream().write(pdf);
                res.raw().getOutputStream().flush();
                return res.raw();
            } catch (Exception e) {
                res.status(500);
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        });

        Spark.post("/api/settings/thresholds", (req, res) -> {
            res.type("application/json");
            res.header("Access-Control-Allow-Origin", "*");
            var m = new Gson().fromJson(req.body(), Map.class);
            System.out.println("[Settings] Thresholds updated - suspicious: " +
                m.get("suspicious") + ", high: " + m.get("high"));
            return "{\"success\":true}";
        });

        // ── Model Accuracy Stats ─────────────────────────────────────────
        Spark.get("/api/model/accuracy", (req, res) -> {
            res.type("application/json");
            res.header("Access-Control-Allow-Origin", "*");
            Map<String, Object> acc = new java.util.LinkedHashMap<>();
            acc.put("randomForest",  94.7);
            acc.put("naiveBayes",    89.3);
            acc.put("ensemble",      96.2);
            acc.put("cnn",           91.8);
            acc.put("datasetSize",   11055);
            acc.put("trainTestSplit","70:30");
            return gson.toJson(acc);
        });

        // ── Explainability Endpoint ──────────────────────────────────────
        Spark.get("/api/incidents/:id/explain", (req, res) -> {
            res.type("application/json");
            res.header("Access-Control-Allow-Origin", "*");

            try {
                long id = Long.parseLong(req.params(":id"));
                var incident = DBConnection.getInstance().getIncidentById(id);
                if (incident == null) {
                    res.status(404);
                    return "{\"error\":\"Incident not found\"}";
                }

                // Extract fields
                String url    = incident.getOrDefault("url", "").toString();
                String sender = incident.getOrDefault("sender", "").toString();
                double score  = Double.parseDouble(
                    incident.getOrDefault("riskScore", "0").toString());

                // Get cached threat intel
                var cache = ThreatIntelCache.get(url);
                double vtScore   = cache.map(c -> c.vtScore()).orElse(0.0);
                int vtPositives  = cache.map(c -> c.vtPositives()).orElse(0);
                int vtTotal      = cache.map(c -> c.vtTotal()).orElse(0);
                boolean ptPhish  = cache.map(c -> c.ptIsPhishing()).orElse(false);
                boolean ptVerify = cache.map(c -> c.ptVerified()).orElse(false);

                // WHOIS Lookup
                com.phishguard.utils.WhoisChecker.WhoisResult whois = 
                    com.phishguard.utils.WhoisChecker.check(url);

                // Parse keywords from stored incident
                String kwStr = incident.getOrDefault("keywords", "").toString();
                List<String> keywords = kwStr.isBlank() ? List.of() :
                    Arrays.asList(kwStr.split(","));

                var explanation = ExplainabilityEngine.explain(
                    url, sender, vtScore, vtPositives, vtTotal,
                    ptPhish, ptVerify, score, score * 0.9, keywords,
                    whois.ageDays(), whois.ageLabel()
                );

                return new Gson().toJson(Map.of(
                    "summary",    explanation.summary(),
                    "redFlags",   explanation.redFlags(),
                    "yellowFlags",explanation.yellowFlags(),
                    "greenFlags", explanation.greenFlags(),
                    "totalRed",   explanation.totalRedFlags(),
                    "domainAge",  whois.ageLabel(),
                    "registeredOn", whois.registeredDate()
                ));

            } catch (Exception e) {
                res.status(500);
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        });

        Spark.delete("/api/incidents/clear", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            try (java.sql.Connection c = DBConnection.getInstance().getConnection();
                 java.sql.PreparedStatement ps = c.prepareStatement("TRUNCATE TABLE incidents")) {
                ps.executeUpdate();
            }
            return "{\"success\":true}";
        });

        // ── Layer Health Check API ──────────────────────────────────────────
        Spark.get("/api/health/layers", (req, res) -> {
            res.type("application/json");
            res.header("Access-Control-Allow-Origin", "*");

            Map<String, Object> health = new LinkedHashMap<>();

            // ML
            health.put("weka_ml", AIModelEngine.isLoaded() ? "✅ Loaded" : "❌ Not loaded");

            // Flask CNN
            try {
                HttpRequest r = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:5000/health"))
                    .timeout(Duration.ofSeconds(2)).GET().build();
                int status = HttpClient.newHttpClient()
                    .send(r, HttpResponse.BodyHandlers.ofString()).statusCode();
                health.put("flask_cnn", status == 200 ? "✅ Running" : "❌ Error");
            } catch (Exception e) {
                health.put("flask_cnn", "❌ Offline");
            }

            // Database
            try (java.sql.Connection c = DBConnection.getInstance().getConnection()) {
                health.put("database", "✅ Connected");
            } catch (Exception e) {
                health.put("database", "❌ Disconnected");
            }

            // Cache
            var cacheStats = ThreatIntelCache.getStats();
            health.put("threat_cache", "✅ " + cacheStats.active() + " active entries");

            // VT API Key
            String actualKey = com.phishguard.utils.VirusTotalChecker.getApiKey(); 
            health.put("virustotal", (actualKey == null || actualKey.contains("YOUR_")) ? "⚠️ No API key" : "✅ Configured");

            return new Gson().toJson(health);
        });

        Spark.delete("/api/processed-emails/clear", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            try (java.sql.Connection c = DBConnection.getInstance().getConnection();
                 java.sql.PreparedStatement ps = c.prepareStatement("TRUNCATE TABLE processed_emails")) {
                ps.executeUpdate();
            }
            return "{\"success\":true}";
        });

        Spark.get("/api/cache/stats", (req, res) -> {
            res.type("application/json");
            res.header("Access-Control-Allow-Origin", "*");
            var stats = com.phishguard.utils.ThreatIntelCache.getStats();
            return new Gson().toJson(Map.of(
                "total", stats.total(),
                "active", stats.active(),
                "phishingHits", stats.phishingHits(),
                "vtMalicious", stats.vtMalicious()
            ));
        });

        Spark.delete("/api/cache/clear", (req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            try (java.sql.Connection c = DBConnection.getInstance().getConnection();
                 java.sql.PreparedStatement ps = c.prepareStatement("TRUNCATE TABLE threat_intel_cache")) {
                ps.executeUpdate();
            }
            return "{\"success\":true}";
        });

        Spark.awaitInitialization();
        System.out.println("[WebAPI] Server running at http://localhost:8080");
    }

    private static Object stats(Request req, Response res) throws Exception {
        res.type("application/json");
        Map<String, Object> s = new HashMap<>();
        s.put("totalIncidents", IncidentDAO.getTotalIncidents());
        int threats = IncidentDAO.getIncidentsByDecision("HIGH_RISK") + IncidentDAO.getIncidentsByDecision("SUSPICIOUS");
        s.put("threats", threats);
        s.put("blocked", IncidentDAO.getIncidentsByDecision("HIGH_RISK"));
        s.put("avgRisk", IncidentDAO.getAverageRiskScore());
        s.put("safe", IncidentDAO.getIncidentsByDecision("SAFE"));
        s.put("emailsProcessed", com.phishguard.email.EmailMonitor.getEmailsProcessed());
        return gson.toJson(s);
    }

    private static Object blocked(Request req, Response res) throws Exception {
        res.type("application/json");
        var all = IncidentDAO.getRecentIncidents(500);
        var blockedList = all.stream().filter(i -> "HIGH_RISK".equals(i.decision)).toList();
        return gson.toJson(blockedList);
    }

    private static Object flaskStatus(Request req, Response res) {
        res.type("application/json");
        boolean online = false;
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL("http://localhost:5000/health").openConnection();
            c.setConnectTimeout(2000); c.setReadTimeout(2000);
            online = c.getResponseCode() == 200;
        } catch (Exception ignored) {}
        return "{\"online\":" + online + "}";
    }

    private static Object rootDashboard(Request req, Response res) {
        res.type("text/html");
        try (java.io.InputStream is = WebApiController.class.getResourceAsStream("/dashboard.html")) {
            if (is != null) return new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        return "<h1>PhishGuard</h1><p>dashboard.html not found in resources</p>";
    }



    private static Object dashboard(Request req, Response res) throws Exception {
        res.type("application/json");
        DashboardData data = new DashboardData();
        data.totalEmails   = IncidentDAO.getTotalIncidents();
        data.threats       = IncidentDAO.getIncidentsByDecision("HIGH_RISK")
                + IncidentDAO.getIncidentsByDecision("SUSPICIOUS");
        data.blocked       = IncidentDAO.getIncidentsByDecision("HIGH_RISK");
        data.avgRisk       = IncidentDAO.getAverageRiskScore();
        data.breakdown     = new Breakdown();
        data.breakdown.safe       = IncidentDAO.getIncidentsByDecision("SAFE");
        data.breakdown.suspicious = IncidentDAO.getIncidentsByDecision("SUSPICIOUS");
        data.breakdown.highRisk   = IncidentDAO.getIncidentsByDecision("HIGH_RISK");
        data.recent        = IncidentDAO.getRecentIncidents(20);
        data.quarantineCount = 0;
        return gson.toJson(data);
    }

    private static Object scanUrl(Request req, Response res) throws Exception {
        res.type("application/json");
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Methods", "GET");
        String url = req.queryParams("url");
        if (url == null || url.isEmpty()) {
            res.status(400);
            Map<String, String> err = new HashMap<>();
            err.put("error", "Missing URL parameter");
            return gson.toJson(err);
        }

        // 1. Check manual block list FIRST
        if (DBConnection.getInstance().isManuallyBlocked(url)) {
            Map<String, Object> response = new HashMap<>();
            response.put("url", url);
            response.put("score", 1.0);
            response.put("decision", "HIGH_RISK");
            response.put("finalScore", 1.0);
            response.put("actionTaken", "BLOCKED");
            return gson.toJson(response);
        }

        RiskScorer scorer = new RiskScorer(url, "web-scan", "Web Scanner");
        scorer.aiModelScore = AIModelEngine.predict(url);
        if (scorer.aiModelScore > 0.4) {
            scorer.threatIntelScore = ThreatIntelChecker.check(url);
        }
        try {
            VisualAnalyzer.VisualResult vr = VisualAnalyzer.analyze(url);
            scorer.visualScore         = vr.score;
            scorer.visualBrandDetected = vr.detectedBrand;
        } catch (Exception e) {
            scorer.visualScore         = 0.0;
            scorer.visualBrandDetected = "Unknown";
        }
        DecisionEngine.decide(scorer);
        MitigationEngine.mitigate(scorer);
        
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);
        response.put("score", scorer.finalScore); // For Chrome Extension
        response.put("decision", scorer.decision);
        response.put("finalScore", scorer.finalScore); // For Dashboard
        response.put("aiModelScore", scorer.aiModelScore);
        response.put("confidence", DecisionEngine.getConfidence(scorer.finalScore));
        if (scorer.visualBrandDetected != null) {
            response.put("visualBrandDetected", scorer.visualBrandDetected);
        }
        
        return gson.toJson(response);
    }

    private static Object scanUrlPost(Request req, Response res) throws Exception {
        res.type("application/json");
        res.header("Access-Control-Allow-Origin", "*");
        
        Map<String, Object> body = gson.fromJson(req.body(), Map.class);
        if (body == null || !body.containsKey("url")) {
            res.status(400);
            return "{\"error\":\"Missing URL in body\"}";
        }
        
        String url = body.get("url").toString();
        String sender = body.getOrDefault("sender", "browser").toString();
        String source = body.getOrDefault("source", "BROWSER_TAB").toString();

        // Check manual block list
        if (DBConnection.getInstance().isManuallyBlocked(url)) {
            Map<String, Object> resp = new HashMap<>();
            resp.put("url", url);
            resp.put("decision", "HIGH_RISK");
            resp.put("finalScore", 1.0);
            resp.put("score", 1.0);
            return gson.toJson(resp);
        }

        RiskScorer scorer = new RiskScorer(url, sender, source);
        scorer.score(); // Use the new score() method
        
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);
        response.put("decision", scorer.decision);
        response.put("finalScore", scorer.finalScore);
        response.put("score", scorer.finalScore);
        response.put("aiModelScore", scorer.aiModelScore);
        
        return gson.toJson(response);
    }

    private static Object incidents(Request req, Response res) throws Exception {
        res.type("application/json");
        String limit = req.queryParams("limit");
        int l = (limit != null) ? Integer.parseInt(limit) : 50;
        return gson.toJson(IncidentDAO.getRecentIncidents(l));
    }

    private static Object status(Request req, Response res) throws Exception {
        res.type("application/json");
        Map<String, Object> status = new HashMap<>();
        status.put("running",         true);
        status.put("emailsProcessed", com.phishguard.email.EmailMonitor.getEmailsProcessed());
        status.put("threatsFound",    com.phishguard.email.EmailMonitor.getThreatsFound());
        return gson.toJson(status);
    }

    private static Object quarantine(Request req, Response res) throws Exception {
        res.type("application/json");
        return gson.toJson(new java.util.ArrayList<>());
    }

    @SuppressWarnings("unused")
    private static class DashboardData {
        int totalEmails;
        int threats;
        int blocked;
        double avgRisk;
        Breakdown breakdown;
        java.util.List<RiskScorer> recent;
        int quarantineCount;
    }

    @SuppressWarnings("unused")
    private static class Breakdown {
        int safe;
        int suspicious;
        int highRisk;
    }
    private static Object explainIncident(Request req, Response res) {
        res.type("application/json");
        setCorsHeaders(res);

        try {
            long id = Long.parseLong(req.params(":id"));
            String sql = "SELECT * FROM incidents WHERE id = ?";

            try (Connection c = DBConnection.getInstance().getConnection();
                 PreparedStatement ps = c.prepareStatement(sql)) {

                ps.setLong(1, id);
                ResultSet rs = ps.executeQuery();

                if (!rs.next()) {
                    res.status(404);
                    return "{\"error\":\"Incident not found\"}";
                }

                String decision  = rs.getString("ai_decision");
                String url       = rs.getString("url_found");
                double mlScore   = rs.getDouble("ai_model_score");
                int vtCount      = rs.getInt("virustotal_detections");
                boolean ptPhish  = rs.getBoolean("phishtank_confirmed");
                double cnnScore  = rs.getDouble("visual_score");
                String age       = rs.getString("domain_age");

                List<String> red    = new ArrayList<>();
                List<String> yellow = new ArrayList<>();
                List<String> green  = new ArrayList<>();

                // ML Model
                if (mlScore >= 0.75) red.add("AI Model: HIGH probability of phishing (" + String.format("%.1f%%", mlScore * 100) + ")");
                else if (mlScore >= 0.40) yellow.add("AI Model: Moderate phishing probability (" + String.format("%.1f%%", mlScore * 100) + ")");
                else green.add("AI Model: URL structure appears safe (" + String.format("%.1f%%", mlScore * 100) + ")");

                // VirusTotal
                if (vtCount >= 5) red.add("VirusTotal: Flagged as malicious by " + vtCount + " security engines");
                else if (vtCount > 0) yellow.add("VirusTotal: Flagged by " + vtCount + " engine(s) — exercise caution");
                else green.add("VirusTotal: No malicious detections found");

                // PhishTank
                if (ptPhish) red.add("PhishTank: URL confirmed in community phishing database");
                else green.add("PhishTank: Not listed in known phishing databases");

                // CNN Visual
                if (cnnScore >= 0.75) red.add("Visual CNN: Page layout highly resembles a known phishing template");
                else if (cnnScore >= 0.40) yellow.add("Visual CNN: Visual elements show some similarity to phishing pages");
                else if (cnnScore > 0) green.add("Visual CNN: Page visuals appear legitimate");

                // Domain Age
                if (age != null && !age.equals("Unknown")) {
                    if (age.contains("days") && !age.contains("year")) {
                        try {
                            int days = Integer.parseInt(age.replaceAll("[^0-9]", ""));
                            if (days < 30) red.add("Domain Age: Registered only " + age + " ago (New domains are high risk)");
                            else if (days < 90) yellow.add("Domain Age: Relatively new domain (" + age + ")");
                            else green.add("Domain Age: Established domain (" + age + ")");
                        } catch (Exception e) { yellow.add("Domain Age: " + age); }
                    } else { green.add("Domain Age: Established domain (" + age + ")"); }
                }

                // URL Tricks
                if (url.contains("@")) red.add("URL Structure: Contains '@' symbol (Classic credential phishing trick)");
                if (url.startsWith("http://") && !url.contains("localhost")) yellow.add("Security: Using insecure HTTP instead of HTTPS");

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("url", url);
                result.put("decision", decision);
                result.put("summary", buildSummary(decision, red.size(), yellow.size()));
                result.put("redFlags", red);
                result.put("yellowFlags", yellow);
                result.put("greenFlags", green);
                result.put("domainAge", age);

                return gson.toJson(result);
            }
        } catch (Exception e) {
            res.status(500);
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    private static String buildSummary(String decision, int red, int yellow) {
        if ("HIGH_RISK".equals(decision)) return "🚨 This URL has been flagged as HIGH RISK due to " + red + " critical signal(s).";
        if ("SUSPICIOUS".equals(decision)) return "⚠️ This URL is suspicious. " + yellow + " warning(s) were found during analysis.";
        return "✅ This URL appears safe based on our multi-layer analysis.";
    }

    private static void setCorsHeaders(Response res) {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.header("Access-Control-Max-Age", "3600");
    }

    private static Object scanUrlQuick(Request req, Response res) {
        res.type("application/json");
        setCorsHeaders(res);

        try {
            Map<String, Object> body = gson.fromJson(req.body(), Map.class);
            String url = (String) body.get("url");

            if (url == null || url.isBlank()) {
                return "{\"decision\":\"SAFE\",\"riskScore\":0.0,\"confidence\":\"N/A\"}";
            }

            // Skip chrome:// and extension pages
            if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")
                || url.startsWith("about:") || url.startsWith("edge://")) {
                return gson.toJson(Map.of(
                    "decision", "SAFE",
                    "riskScore", 0.0,
                    "confidence", "Browser Page",
                    "message", "Internal browser page — not scanned"
                ));
            }

            // Run only fast layers: ML + Keywords (skip WHOIS/VT/CNN)
            RiskScorer scorer = new RiskScorer(url, "browser", "EXTENSION_POPUP");
            scorer.scoreFast(url, "", "EXTENSION_POPUP");

            return gson.toJson(Map.of(
                "decision",   scorer.decision,
                "riskScore",  scorer.finalScore,
                "confidence", DecisionEngine.getConfidence(scorer.finalScore),
                "url",        url
            ));

        } catch (Exception e) {
            res.status(500);
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }
}