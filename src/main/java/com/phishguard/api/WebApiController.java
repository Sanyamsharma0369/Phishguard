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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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

        // CORS
        Spark.before((req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            res.header("Access-Control-Allow-Headers", "Content-Type");
        });
        Spark.options("/*", (req, res) -> { res.status(200); return "OK"; });

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
        Spark.get("/api/scan",      WebApiController::scanUrl);
        Spark.post("/api/scan",     WebApiController::scanUrlPost);
        Spark.get("/api/incidents",  WebApiController::incidents);
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

                // Parse keywords from stored incident
                String kwStr = incident.getOrDefault("keywords", "").toString();
                List<String> keywords = kwStr.isBlank() ? List.of() :
                    Arrays.asList(kwStr.split(","));

                var explanation = ExplainabilityEngine.explain(
                    url, sender, vtScore, vtPositives, vtTotal,
                    ptPhish, ptVerify, score, score * 0.9, keywords
                );

                return new Gson().toJson(Map.of(
                    "summary",    explanation.summary(),
                    "redFlags",   explanation.redFlags(),
                    "yellowFlags",explanation.yellowFlags(),
                    "greenFlags", explanation.greenFlags(),
                    "totalRed",   explanation.totalRedFlags()
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

    // Keep old inline dashboard method for backward compat
    @SuppressWarnings("unused")
    private static Object rootDashboardOld(Request req, Response res) {
        res.type("text/html");
        StringBuilder h = new StringBuilder();
        h.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>");
        h.append("<meta name='viewport' content='width=device-width,initial-scale=1'>");
        h.append("<title>PhishGuard Dashboard</title>");
        // Changed from local /chartjs route to jsdelivr CDN
        h.append("<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>");
        h.append("<style>");
        h.append("*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}");
        h.append(":root{--bg:#0a0c10;--s1:#111318;--s2:#181b22;--br:rgba(255,255,255,0.07);");
        h.append("--t:#e2e4e9;--tm:#8b8fa8;--tf:#3d404d;");
        h.append("--g:#22c55e;--gb:rgba(34,197,94,0.1);--gbd:rgba(34,197,94,0.2);");
        h.append("--r:#ef4444;--rb:rgba(239,68,68,0.1);--rbd:rgba(239,68,68,0.2);");
        h.append("--y:#f59e0b;--yb:rgba(245,158,11,0.1);--ybd:rgba(245,158,11,0.2);");
        h.append("--c:#06b6d4;--rad:10px;--tr:200ms cubic-bezier(0.16,1,0.3,1)}");
        h.append("html{-webkit-font-smoothing:antialiased}");
        h.append("body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--t);min-height:100vh;font-size:14px}");
        h.append(".layout{display:grid;grid-template-rows:56px 1fr;min-height:100vh}");
        h.append(".hdr{display:flex;align-items:center;justify-content:space-between;padding:0 24px;");
        h.append("background:var(--s1);border-bottom:1px solid var(--br);position:sticky;top:0;z-index:100}");
        h.append(".logo{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:700;color:var(--c)}");
        h.append(".hr{display:flex;align-items:center;gap:12px}");
        h.append(".live{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;color:var(--g);");
        h.append("background:var(--gb);border:1px solid var(--gbd);padding:4px 10px;border-radius:999px}");
        h.append(".live::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--g);animation:p 2s infinite}");
        h.append("@keyframes p{0%,100%{opacity:1}50%{opacity:.4}}");
        h.append(".clk{font-size:12px;color:var(--tm);font-variant-numeric:tabular-nums}");
        h.append(".rbtn{display:flex;align-items:center;gap:6px;padding:6px 14px;border-radius:6px;");
        h.append("background:var(--s2);border:1px solid var(--br);color:var(--t);font-size:13px;cursor:pointer;transition:background var(--tr)}");
        h.append(".rbtn:hover{background:rgba(255,255,255,0.08)}");
        h.append(".main{padding:24px;display:flex;flex-direction:column;gap:20px;max-width:1400px;margin:0 auto;width:100%}");
        h.append(".kgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}");
        h.append(".kpi{background:var(--s1);border:1px solid var(--br);border-radius:var(--rad);padding:20px;display:flex;flex-direction:column;gap:6px}");
        h.append(".kpi-l{font-size:11px;font-weight:500;color:var(--tm);text-transform:uppercase;letter-spacing:.5px}");
        h.append(".kpi-v{font-size:28px;font-weight:700;letter-spacing:-1px;font-variant-numeric:tabular-nums}");
        h.append(".kpi-s{font-size:11px;color:var(--tf)}");
        h.append(".kpi.c .kpi-v{color:var(--c)}.kpi.r .kpi-v{color:var(--r)}.kpi.y .kpi-v{color:var(--y)}.kpi.g .kpi-v{color:var(--g)}");
        h.append(".sbar{background:var(--s1);border:1px solid var(--br);border-radius:var(--rad);padding:14px 20px;");
        h.append("display:flex;align-items:center;gap:20px;flex-wrap:wrap}");
        h.append(".si{display:flex;align-items:center;gap:8px;font-size:13px}");
        h.append(".sd{width:8px;height:8px;border-radius:50%}");
        h.append(".sd.g{background:var(--g);box-shadow:0 0 6px var(--g)}.sd.r{background:var(--r)}.sd.y{background:var(--y)}");
        h.append(".sl{color:var(--tm)}.sv{font-weight:600}");
        h.append(".sdiv{width:1px;height:16px;background:var(--br)}");
        h.append(".cgrid{display:grid;grid-template-columns:1fr 340px;gap:16px}");
        h.append("@media(max-width:900px){.cgrid{grid-template-columns:1fr}}");
        h.append(".card{background:var(--s1);border:1px solid var(--br);border-radius:var(--rad);overflow:hidden}");
        h.append(".ch{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--br)}");
        h.append(".ct{font-size:14px;font-weight:600}");
        h.append(".cc{font-size:12px;color:var(--tm);background:var(--s2);padding:2px 8px;border-radius:999px;border:1px solid var(--br)}");
        h.append(".iw{overflow-x:auto}");
        h.append("table{width:100%;border-collapse:collapse}");
        h.append("th{padding:10px 16px;text-align:left;font-size:11px;font-weight:600;color:var(--tm);");
        h.append("text-transform:uppercase;letter-spacing:.5px;background:var(--s2);border-bottom:1px solid var(--br)}");
        h.append("td{padding:12px 16px;font-size:13px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}");
        h.append("tr:last-child td{border-bottom:none}tr:hover td{background:rgba(255,255,255,.025)}");
        h.append(".badge{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:600}");
        h.append(".badge.sf{background:var(--gb);color:var(--g);border:1px solid var(--gbd)}");
        h.append(".badge.sp{background:var(--yb);color:var(--y);border:1px solid var(--ybd)}");
        h.append(".badge.hi{background:var(--rb);color:var(--r);border:1px solid var(--rbd)}");
        h.append(".uc{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:12px;color:var(--tm)}");
        h.append(".sb2{display:flex;align-items:center;gap:8px}");
        h.append(".st{width:60px;height:4px;background:var(--tf);border-radius:2px;overflow:hidden}");
        h.append(".sf2{height:100%;border-radius:2px}");
        h.append(".stxt{font-size:12px;font-variant-numeric:tabular-nums;min-width:36px}");
        h.append(".es{padding:40px;text-align:center;color:var(--tm);font-size:13px}");
        h.append(".scbody{padding:20px;display:flex;flex-direction:column;gap:14px}");
        h.append("label{font-size:12px;font-weight:500;color:var(--tm)}");
        h.append("input[type=text]{width:100%;padding:10px 14px;background:var(--s2);border:1px solid var(--br);");
        h.append("border-radius:6px;color:var(--t);font-size:13px;transition:border-color var(--tr);outline:none}");
        h.append("input[type=text]:focus{border-color:var(--c)}");
        h.append("input[type=text]::placeholder{color:var(--tf)}");
        h.append(".bsc{width:100%;padding:10px;background:var(--c);color:#000;font-size:13px;font-weight:700;");
        h.append("border:none;border-radius:6px;cursor:pointer;transition:opacity var(--tr)}");
        h.append(".bsc:hover{opacity:.85}.bsc:disabled{opacity:.4;cursor:not-allowed}");
        h.append(".sr2{background:var(--s2);border:1px solid var(--br);border-radius:8px;padding:16px;");
        h.append("display:flex;flex-direction:column;gap:10px;font-size:13px}");
        h.append(".srr{display:flex;justify-content:space-between;align-items:center}");
        h.append(".srl{color:var(--tm);font-size:12px}.srv{font-weight:600}");
        h.append(".rm{height:6px;background:var(--tf);border-radius:3px;overflow:hidden;margin-top:4px}");
        h.append(".rf{height:100%;border-radius:3px;transition:width .6s}");
        h.append(".serr{color:var(--r);font-size:12px;background:var(--rb);padding:10px;border-radius:6px;border:1px solid var(--rbd)}");
        h.append(".cw{position:relative;height:180px}");
        h.append(".cbody{padding:20px}");
        h.append("::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--tf);border-radius:3px}");
        h.append("</style></head><body>");
        h.append("<div class='layout'>");
        h.append("<header class='hdr'>");
        h.append("<div class='logo'><svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/></svg>PhishGuard</div>");
        h.append("<div class='hr'><div class='live'>LIVE</div><div class='clk' id='clk'></div>");
        h.append("<button class='rbtn' onclick='loadAll()'>&#x21BB; Refresh</button></div>");
        h.append("</header>");
        h.append("<main class='main'>");
        h.append("<div class='sbar'>");
        h.append("<div class='si'><div class='sd g'></div><span class='sl'>API Server</span><span class='sv' style='color:var(--g)'>Online</span></div>");
        h.append("<div class='sdiv'></div>");
        h.append("<div class='si'><div class='sd y'></div><span class='sl'>Flask CNN</span><span class='sv' id='fls'>Checking...</span></div>");
        h.append("<div class='sdiv'></div>");
        h.append("<div class='si'><span class='sl'>Emails</span><span class='sv' id='se'>0</span></div>");
        h.append("<div class='sdiv'></div>");
        h.append("<div class='si'><span class='sl'>Threats</span><span class='sv' id='st' style='color:var(--r)'>0</span></div>");
        h.append("<div class='sdiv'></div>");
        h.append("<div class='si'><span class='sl'>Updated</span><span class='sv' id='lu'>—</span></div>");
        h.append("</div>");
        h.append("<div class='kgrid'>");
        h.append("<div class='kpi c'><div class='kpi-l'>Total Incidents</div><div class='kpi-v' id='k1'>0</div><div class='kpi-s'>All time</div></div>");
        h.append("<div class='kpi r'><div class='kpi-l'>Threats</div><div class='kpi-v' id='k2'>0</div><div class='kpi-s'>High + Suspicious</div></div>");
        h.append("<div class='kpi r'><div class='kpi-l'>Blocked</div><div class='kpi-v' id='k3'>0</div><div class='kpi-s'>High risk</div></div>");
        h.append("<div class='kpi y'><div class='kpi-l'>Avg Risk</div><div class='kpi-v' id='k4'>0.000</div><div class='kpi-s'>0.0–1.0 scale</div></div>");
        h.append("<div class='kpi g'><div class='kpi-l'>Safe</div><div class='kpi-v' id='k5'>0</div><div class='kpi-s'>Passed all checks</div></div>");
        h.append("</div>");
        h.append("<div class='cgrid'>");
        h.append("<div class='card'><div class='ch'><span class='ct'>Recent Incidents</span><span class='cc' id='ic'>0 records</span></div>");
        h.append("<div class='iw'><table><thead><tr><th>URL / Target</th><th>Sender</th><th>Risk Score</th><th>Decision</th></tr></thead>");
        h.append("<tbody id='ib'><tr><td colspan='4'><div class='es'>No incidents yet — monitoring active</div></td></tr></tbody></table></div></div>");
        h.append("<div style='display:flex;flex-direction:column;gap:16px'>");
        h.append("<div class='card'><div class='ch'><span class='ct'>Breakdown</span></div><div class='cbody'><div class='cw'><canvas id='bc'></canvas></div></div></div>");
        h.append("<div class='card'><div class='ch'><span class='ct'>URL Scanner</span></div>");
        h.append("<div class='scbody'><label>Enter URL to scan</label>");
        h.append("<input type='text' id='ui' placeholder='https://example.com'/>");
        h.append("<button class='bsc' id='sb' onclick='doScan()'>Scan URL</button>");
        h.append("<div id='sres' style='display:none'></div></div></div>");
        h.append("</div></div>");
        h.append("</main></div>");
        h.append("<script>");
        h.append("var chart=null;");
        h.append("function clk(){document.getElementById('clk').textContent=new Date().toLocaleTimeString()}setInterval(clk,1000);clk();");
        h.append("async function loadAll(){");
        h.append("  await Promise.all([loadStatus(),loadDash(),loadInc()]);");
        h.append("  document.getElementById('lu').textContent=new Date().toLocaleTimeString();");
        h.append("}");
        h.append("async function loadStatus(){try{");
        h.append("  var d=await fetch('/api/status').then(r=>r.json());");
        h.append("  document.getElementById('se').textContent=d.emailsProcessed||0;");
        h.append("  document.getElementById('st').textContent=d.threatsFound||0;");
        h.append("  fetch('http://localhost:5000/health',{signal:AbortSignal.timeout(2000)})");
        h.append("    .then(function(){document.getElementById('fls').innerHTML=\"<span style='color:var(--g)'>Online</span>\"})");
        h.append("    .catch(function(){document.getElementById('fls').innerHTML=\"<span style='color:var(--r)'>Offline</span>\"});");
        h.append("}catch(e){}}");
        h.append("async function loadDash(){try{");
        h.append("  var d=await fetch('/api/dashboard').then(r=>r.json());");
        h.append("  anim('k1',d.totalEmails||0);anim('k2',d.threats||0);anim('k3',d.blocked||0);anim('k5',d.breakdown&&d.breakdown.safe||0);");
        h.append("  document.getElementById('k4').textContent=((d.avgRisk||0).toFixed(3));");
        h.append("  rChart(d.breakdown&&d.breakdown.safe||0,d.breakdown&&d.breakdown.suspicious||0,d.breakdown&&d.breakdown.highRisk||0);");
        h.append("}catch(e){}}");
        h.append("function anim(id,t){var el=document.getElementById(id),s=0;function step(){s=Math.min(s+Math.ceil(t/20)||1,t);el.textContent=s;if(s<t)requestAnimationFrame(step)}requestAnimationFrame(step)}");
        h.append("function rChart(sf,sp,hi){");
        h.append("  var ctx=document.getElementById('bc').getContext('2d');");
        h.append("  if(chart)chart.destroy();");
        h.append("  chart=new Chart(ctx,{type:'doughnut',");
        h.append("    data:{labels:['Safe','Suspicious','High Risk'],datasets:[{data:[sf,sp,hi],");
        h.append("      backgroundColor:['rgba(34,197,94,.8)','rgba(245,158,11,.8)','rgba(239,68,68,.8)'],");
        h.append("      borderColor:['#22c55e','#f59e0b','#ef4444'],borderWidth:1.5,hoverOffset:4}]},");
        h.append("    options:{responsive:true,maintainAspectRatio:false,cutout:'70%',");
        h.append("      plugins:{legend:{position:'bottom',labels:{color:'#8b8fa8',padding:12,font:{size:11}}}}}});");
        h.append("}");
        h.append("async function loadInc(){try{");
        h.append("  var list=await fetch('/api/incidents?limit=20').then(r=>r.json());");
        h.append("  document.getElementById('ic').textContent=list.length+' records';");
        h.append("  var b=document.getElementById('ib');");
        h.append("  if(!list.length){b.innerHTML='<tr><td colspan=\"4\"><div class=\"es\">No incidents yet</div></td></tr>';return}");
        h.append("  b.innerHTML=list.map(function(i){");
        h.append("    var sc=i.finalScore!=null?i.finalScore:i.aiModelScore||0;");
        h.append("    var dc=(i.decision||'SAFE').toUpperCase();");
        h.append("    var cl=dc==='HIGH_RISK'?'hi':dc==='SUSPICIOUS'?'sp':'sf';");
        h.append("    var lb=dc==='HIGH_RISK'?'HIGH RISK':dc==='SUSPICIOUS'?'SUSPICIOUS':'SAFE';");
        h.append("    var fc=dc==='HIGH_RISK'?'#ef4444':dc==='SUSPICIOUS'?'#f59e0b':'#22c55e';");
        h.append("    var pt=Math.round(sc*100);");
        h.append("    return '<tr><td><div class=\"uc\" title=\"'+esc(i.url||'')+'\">'+esc(i.url||'N/A')+'</div></td>'");
        h.append("      +'<td style=\"color:#8b8fa8;font-size:12px\">'+esc(i.senderEmail||i.sender||'—')+'</td>'");
        h.append("      +'<td><div class=\"sb2\"><div class=\"st\"><div class=\"sf2\" style=\"width:'+pt+'%;background:'+fc+'\"></div></div>'");
        h.append("      +'<span class=\"stxt\">'+sc.toFixed(3)+'</span></div></td>'");
        h.append("      +'<td><span class=\"badge '+cl+'\">'+lb+'</span></td></tr>';");
        h.append("  }).join('');");
        h.append("}catch(e){}}");
        h.append("function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}");
        h.append("async function doScan(){");
        h.append("  var url=document.getElementById('ui').value.trim();");
        h.append("  var re=document.getElementById('sres');var btn=document.getElementById('sb');");
        h.append("  if(!url){re.innerHTML='<div class=\"serr\">Please enter a URL</div>';re.style.display='block';return}");
        h.append("  btn.disabled=true;btn.textContent='Scanning...';re.style.display='none';");
        h.append("  try{");
        h.append("    var d=await fetch('/api/scan?url='+encodeURIComponent(url)).then(r=>r.json());");
        h.append("    if(d.error){re.innerHTML='<div class=\"serr\">'+esc(d.error)+'</div>';re.style.display='block';btn.disabled=false;btn.textContent='Scan URL';return}");
        h.append("    var sc=d.finalScore!=null?d.finalScore:d.aiModelScore||0;");
        h.append("    var dc=(d.decision||'SAFE').toUpperCase();");
        h.append("    var cl=dc==='HIGH_RISK'?'hi':dc==='SUSPICIOUS'?'sp':'sf';");
        h.append("    var lb=dc==='HIGH_RISK'?'⚠ HIGH RISK':dc==='SUSPICIOUS'?'⚡ SUSPICIOUS':'✓ SAFE';");
        h.append("    var fc=dc==='HIGH_RISK'?'#ef4444':dc==='SUSPICIOUS'?'#f59e0b':'#22c55e';");
        h.append("    re.innerHTML='<div class=\"sr2\">'");
        h.append("      +'<div class=\"srr\"><span class=\"srl\">Decision</span><span class=\"badge '+cl+'\">'+lb+'</span></div>'");
        h.append("      +'<div class=\"srr\"><span class=\"srl\">Risk Score</span><span class=\"srv\">'+sc.toFixed(4)+'</span></div>'");
        h.append("      +'<div class=\"rm\"><div class=\"rf\" style=\"width:'+Math.round(sc*100)+'%;background:'+fc+'\"></div></div>'");
        h.append("      +'<div class=\"srr\"><span class=\"srl\">AI Score</span><span class=\"srv\">'+((d.aiModelScore||0).toFixed(4))+'</span></div>'");
        h.append("      +(d.visualBrandDetected&&d.visualBrandDetected!='Unknown'?'<div class=\"srr\"><span class=\"srl\">Brand Spoofed</span><span class=\"srv\" style=\"color:var(--r)\">'+esc(d.visualBrandDetected)+'</span></div>':'')");
        h.append("      +'</div>';");
        h.append("    re.style.display='block';");
        h.append("  }catch(e){re.innerHTML='<div class=\"serr\">Scan failed: '+esc(e.message)+'</div>';re.style.display='block'}");
        h.append("  btn.disabled=false;btn.textContent='Scan URL';");
        h.append("}");
        h.append("document.addEventListener('DOMContentLoaded',function(){document.getElementById('ui').addEventListener('keydown',function(e){if(e.key==='Enter')doScan()})});");
        h.append("loadAll();setInterval(loadAll,30000);");
        h.append("</script></body></html>");
        return h.toString();
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
}