package com.phishguard.database;

import com.phishguard.utils.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * PhishGuard - QuarantineDAO.java
 * -------------------------------------------------
 * Data Access Object for the 'quarantine' table.
 *
 * The quarantine table stores domains that have been identified as
 * malicious. Once quarantined, any future email containing that domain
 * is immediately blocked without re-running the full AI pipeline.
 *
 * FAIL-OPEN design: isDomainQuarantined() returns FALSE on DB error.
 * This ensures a DB outage does not prevent legitimate emails from being processed.
 *
 * Usage:
 *   QuarantineDAO.addDomain("paypal-secure.xyz", "PhishTank confirmed");
 *   if (QuarantineDAO.isDomainQuarantined("paypal-secure.xyz")) { ... }
 */
public final class QuarantineDAO {

    private QuarantineDAO() {}

    // ── Write ─────────────────────────────────────────────────────────────

    /**
     * Adds a domain to the quarantine table.
     * If the domain already exists (UNIQUE constraint), increments
     * times_blocked and updates last_attempt timestamp.
     *
     * @param domain registrable domain (e.g., "paypal-secure.xyz")
     * @param reason human-readable reason for quarantine
     */
    public static void addDomain(String domain, String reason) {
        if (domain == null || domain.isBlank()) {
            System.err.println("[QuarantineDAO] Warning: cannot quarantine null/blank domain.");
            return;
        }

        String sql = "INSERT INTO " + Constants.TABLE_QUARANTINE
                   + " (domain, date_added, reason, times_blocked, last_attempt) "
                   + " VALUES (?, CURDATE(), ?, 1, NOW()) "
                   + " ON DUPLICATE KEY UPDATE "
                   + "   times_blocked = times_blocked + 1, "
                   + "   last_attempt  = NOW(), "
                   + "   reason        = VALUES(reason)";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, domain.toLowerCase().trim());
                ps.setString(2, reason != null ? reason : "No reason specified");
                ps.executeUpdate();
                System.out.println("[Quarantine] Domain added: " + domain);
                LogDAO.warning("QUARANTINE_ADDED", "Domain quarantined: " + domain + " | Reason: " + reason);
            }
        } catch (Exception e) {
            System.err.println("[QuarantineDAO] Error adding domain '" + domain + "': " + e.getMessage());
        }
    }

    // ── Read ──────────────────────────────────────────────────────────────

    /**
     * Checks whether a domain is currently in the quarantine table.
     *
     * FAIL-OPEN: returns false on any DB error to avoid blocking legitimate mail
     * during connectivity issues.
     *
     * @param domain registrable domain to check (case-insensitive)
     * @return true if quarantined, false if safe or on DB error
     */
    public static boolean isDomainQuarantined(String domain) {
        if (domain == null || domain.isBlank()) return false;

        String sql = "SELECT COUNT(*) FROM " + Constants.TABLE_QUARANTINE
                   + " WHERE domain = ?";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, domain.toLowerCase().trim());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getInt(1) > 0;
                    }
                }
            }
        } catch (Exception e) {
            // Fail-open: DB error → assume not quarantined
            System.err.println("[QuarantineDAO] Check failed for '" + domain + "': " + e.getMessage());
            return false;
        }
        return false;
    }

    /**
     * Returns all quarantined domains, newest first.
     *
     * @return list of domain strings, or empty list on error
     */
    public static List<String> getAllQuarantinedDomains() {
        List<String> domains = new ArrayList<>();
        String sql = "SELECT domain FROM " + Constants.TABLE_QUARANTINE
                   + " ORDER BY date_added DESC";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    domains.add(rs.getString("domain"));
                }
            }
        } catch (Exception e) {
            System.err.println("[QuarantineDAO] Error fetching all domains: " + e.getMessage());
        }
        return domains;
    }

    /**
     * Returns the total number of quarantined domains.
     *
     * @return count, or 0 on error
     */
    public static int getQuarantineCount() {
        String sql = "SELECT COUNT(*) FROM " + Constants.TABLE_QUARANTINE;
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (Exception e) {
            System.err.println("[QuarantineDAO] Error counting quarantine: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Removes a domain from quarantine (for manual admin override).
     *
     * @param domain domain to remove
     * @return true if removed, false if not found or error
     */
    public static boolean removeDomain(String domain) {
        if (domain == null || domain.isBlank()) return false;
        String sql = "DELETE FROM " + Constants.TABLE_QUARANTINE + " WHERE domain = ?";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, domain.toLowerCase().trim());
                int rows = ps.executeUpdate();
                if (rows > 0) {
                    System.out.println("[QuarantineDAO] Domain removed from quarantine: " + domain);
                    LogDAO.info("QUARANTINE_REMOVED", "Domain un-quarantined: " + domain);
                    return true;
                }
            }
        } catch (Exception e) {
            System.err.println("[QuarantineDAO] Error removing domain '" + domain + "': " + e.getMessage());
        }
        return false;
    }
}
