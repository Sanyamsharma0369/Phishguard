package com.phishguard.utils;

import com.phishguard.database.DBConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Optional;

public class ThreatIntelCache {

    public record CacheResult(
        boolean found,
        double vtScore,
        int vtPositives,
        int vtTotal,
        boolean ptIsPhishing,
        boolean ptVerified,
        String source
    ) {}

    // ── SHA-256 hash of the URL ──────────────────────────────────────────────
    public static String hashUrl(String url) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(url.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return url.hashCode() + "";
        }
    }

    // ── Look up cache (returns empty if expired or missing) ──────────────────
    public static Optional<CacheResult> get(String url) {
        String sql = """
            SELECT vt_score, vt_positives, vt_total, 
                   pt_is_phishing, pt_verified, source
            FROM threat_intel_cache
            WHERE url_hash = ? AND expires_at > NOW()
            LIMIT 1
        """;
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {

            ps.setString(1, hashUrl(url));
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new CacheResult(
                    true,
                    rs.getDouble("vt_score"),
                    rs.getInt("vt_positives"),
                    rs.getInt("vt_total"),
                    rs.getBoolean("pt_is_phishing"),
                    rs.getBoolean("pt_verified"),
                    rs.getString("source")
                ));
            }
        } catch (Exception e) {
            System.err.println("[Cache] GET error: " + e.getMessage());
        }
        return Optional.empty();
    }

    // ── Store result in cache ────────────────────────────────────────────────
    public static void put(String url, double vtScore, int vtPositives, int vtTotal,
                           boolean ptIsPhishing, boolean ptVerified, String source) {
        String sql = """
            INSERT INTO threat_intel_cache 
                (url_hash, url, vt_score, vt_positives, vt_total, 
                 pt_is_phishing, pt_verified, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                vt_score = VALUES(vt_score),
                vt_positives = VALUES(vt_positives),
                vt_total = VALUES(vt_total),
                pt_is_phishing = VALUES(pt_is_phishing),
                pt_verified = VALUES(pt_verified),
                source = VALUES(source),
                created_at = NOW()
        """;
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {

            ps.setString(1, hashUrl(url));
            ps.setString(2, url.length() > 2000 ? url.substring(0, 2000) : url);
            ps.setDouble(3, vtScore);
            ps.setInt(4, vtPositives);
            ps.setInt(5, vtTotal);
            ps.setBoolean(6, ptIsPhishing);
            ps.setBoolean(7, ptVerified);
            ps.setString(8, source);
            ps.executeUpdate();
            System.out.println("[Cache] Stored: " + url.substring(0, Math.min(60, url.length())));
        } catch (Exception e) {
            System.err.println("[Cache] PUT error: " + e.getMessage());
        }
    }

    // ── Purge expired entries (call on startup) ──────────────────────────────
    public static void purgeExpired() {
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(
                 "DELETE FROM threat_intel_cache WHERE expires_at < NOW()")) {
            int deleted = ps.executeUpdate();
            if (deleted > 0)
                System.out.println("[Cache] Purged " + deleted + " expired entries.");
        } catch (Exception e) {
            System.err.println("[Cache] Purge error: " + e.getMessage());
        }
    }

    // ── Stats (for dashboard) ────────────────────────────────────────────────
    public static CacheStats getStats() {
        String sql = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN expires_at > NOW() THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN pt_is_phishing = 1 THEN 1 ELSE 0 END) as phishing_hits,
                SUM(CASE WHEN vt_score > 0.5 THEN 1 ELSE 0 END) as vt_malicious
            FROM threat_intel_cache
        """;
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return new CacheStats(
                    rs.getInt("total"),
                    rs.getInt("active"),
                    rs.getInt("phishing_hits"),
                    rs.getInt("vt_malicious")
                );
            }
        } catch (Exception e) {
            System.err.println("[Cache] Stats error: " + e.getMessage());
        }
        return new CacheStats(0, 0, 0, 0);
    }

    public record CacheStats(int total, int active, int phishingHits, int vtMalicious) {}
}
