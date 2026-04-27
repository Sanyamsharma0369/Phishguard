package com.phishguard.database;

import com.phishguard.utils.ConfigLoader;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PhishGuard - DBConnection.java
 * -------------------------------------------------
 * Singleton JDBC connection to MySQL 8.0.
 */
public class DBConnection {

    // ── Singleton instance ─────────────────────────────────────────────
    private static volatile DBConnection instance;

    private Connection connection;

    // ── Private constructor ────────────────────────────────────────────
    private DBConnection() {
        // Connection is established lazily in getConnection()
    }

    /**
     * Returns the singleton DBConnection manager.
     */
    public static DBConnection getInstance() {
        if (instance == null) {
            synchronized (DBConnection.class) {
                if (instance == null) {
                    instance = new DBConnection();
                }
            }
        }
        return instance;
    }

    // ── Connection management ──────────────────────────────────────────

    public Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                connect();
            }
        } catch (SQLException e) {
            System.err.println("[DB] Connection check failed, attempting reconnect...");
            connect();
        }
        return connection;
    }

    private void connect() {
        ConfigLoader cfg = ConfigLoader.getInstance();
        String url      = cfg.get("db.url",      "jdbc:mysql://localhost:3306/phishguard");
        String user     = cfg.get("db.user",     "root");
        String password = cfg.get("db.password", "");

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(url, user, password);
            connection.setAutoCommit(true);
            System.out.println("[DB] Connected to MySQL: " + url.split("\\?")[0]);
        } catch (Exception e) {
            throw new RuntimeException("[DB] FATAL: Cannot connect to database", e);
        }
    }

    public void close() {
        if (connection != null) {
            try {
                connection.close();
                System.out.println("[DB] Connection closed gracefully.");
            } catch (SQLException e) {
                System.err.println("[DB] Warning: Error while closing connection: " + e.getMessage());
            } finally {
                connection = null;
            }
        }
    }

    public Map<String, Object> getIncidentById(long id) {
        String sql = "SELECT * FROM incidents WHERE id = ?";
        try (Connection c = getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, id);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id",        rs.getLong("id"));
                m.put("url",       rs.getString("url"));
                m.put("sender",    rs.getString("sender"));
                m.put("riskScore", rs.getDouble("risk_score"));
                m.put("decision",  rs.getString("decision"));
                m.put("keywords",  rs.getString("keywords") != null ? 
                                   rs.getString("keywords") : "");
                return m;
            }
        } catch (Exception e) { e.printStackTrace(); }
        return null;
    }

    public boolean isConnected() {
        try {
            return connection != null && !connection.isClosed() && connection.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }

    // ── Whitelist Management ─────────────────────────────────────────────

    public String getAllWhitelist() {
        String sql = "SELECT domain, reason, added_at FROM whitelist ORDER BY added_at DESC";
        StringBuilder json = new StringBuilder("[");
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            boolean first = true;
            while (rs.next()) {
                if (!first) json.append(",");
                json.append(String.format(
                    "{\"domain\":\"%s\",\"reason\":\"%s\",\"addedAt\":\"%s\"}",
                    rs.getString("domain"),
                    rs.getString("reason"),
                    rs.getString("added_at")
                ));
                first = false;
            }
        } catch (Exception e) { e.printStackTrace(); }
        return json.append("]").toString();
    }

    public void addToWhitelist(String domain, String reason) {
        String sql = "INSERT IGNORE INTO whitelist (domain, reason) VALUES (?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, domain);
            ps.setString(2, reason);
            ps.executeUpdate();
            System.out.println("[Whitelist] Added: " + domain);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void removeFromWhitelist(String domain) {
        String sql = "DELETE FROM whitelist WHERE domain = ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, domain);
            ps.executeUpdate();
            System.out.println("[Whitelist] Removed: " + domain);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public boolean isWhitelisted(String url) {
        if (url == null) return false;
        try {
            String domain = url.replaceAll("https?://", "")
                               .replaceAll("www\\.", "")
                               .split("/")[0].toLowerCase();
            String sql = "SELECT 1 FROM whitelist WHERE ? LIKE CONCAT('%', domain)";
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, domain);
                return ps.executeQuery().next();
            }
        } catch (Exception e) { return false; }
    }

    // ── Manual Blocks ─────────────────────────────────────────────────────

    public String getAllManualBlocks() {
        StringBuilder json = new StringBuilder("[");
        String sql = "SELECT domain, reason, added_at FROM manual_blocks ORDER BY added_at DESC";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            boolean first = true;
            while (rs.next()) {
                if (!first) json.append(",");
                json.append(String.format("{\"domain\":\"%s\",\"reason\":\"%s\",\"addedAt\":\"%s\"}",
                    rs.getString("domain"), rs.getString("reason"), rs.getString("added_at")));
                first = false;
            }
        } catch (Exception e) { e.printStackTrace(); }
        return json.append("]").toString();
    }

    public void addManualBlock(String domain, String reason) {
        String sql = "INSERT IGNORE INTO manual_blocks (domain, reason) VALUES (?, ?)";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, domain); ps.setString(2, reason);
            ps.executeUpdate();
            System.out.println("[ManualBlock] Blocked: " + domain);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void removeManualBlock(String domain) {
        String sql = "DELETE FROM manual_blocks WHERE domain = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, domain);
            ps.executeUpdate();
        } catch (Exception e) { e.printStackTrace(); }
    }

    public boolean isManuallyBlocked(String url) {
        if (url == null) return false;
        try {
            String domain = url.replaceAll("https?://", "").replaceAll("www\\.", "").split("/")[0].toLowerCase();
            String sql = "SELECT 1 FROM manual_blocks WHERE ? LIKE CONCAT('%', domain)";
            try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, domain);
                return ps.executeQuery().next();
            }
        } catch (Exception e) { return false; }
    }

    public java.util.Map<String, Object> getStats() {
        java.util.Map<String, Object> s = new java.util.LinkedHashMap<>();
        try {
            s.put("totalIncidents", com.phishguard.database.IncidentDAO.getTotalIncidents());
            int threats = com.phishguard.database.IncidentDAO.getIncidentsByDecision("HIGH_RISK") + 
                          com.phishguard.database.IncidentDAO.getIncidentsByDecision("SUSPICIOUS");
            s.put("threats", threats);
            s.put("blocked", com.phishguard.database.IncidentDAO.getIncidentsByDecision("HIGH_RISK"));
            s.put("avgRisk", com.phishguard.database.IncidentDAO.getAverageRiskScore());
            s.put("safe", com.phishguard.database.IncidentDAO.getIncidentsByDecision("SAFE"));
        } catch (Exception e) {}
        return s;
    }

    public java.util.List<java.util.Map<String,Object>> getRecentIncidentsForReport(int limit) {
        var list = new java.util.ArrayList<java.util.Map<String,Object>>();
        String sql = "SELECT url, sender, risk_score, decision FROM incidents ORDER BY created_at DESC LIMIT ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, limit);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                var m = new java.util.LinkedHashMap<String,Object>();
                m.put("url", rs.getString("url"));
                m.put("sender", rs.getString("sender") != null ? rs.getString("sender") : "—");
                m.put("riskScore", String.format("%.4f", rs.getDouble("risk_score")));
                m.put("decision", rs.getString("decision"));
                list.add(m);
            }
        } catch (Exception e) { e.printStackTrace(); }
        return list;
    }
}
