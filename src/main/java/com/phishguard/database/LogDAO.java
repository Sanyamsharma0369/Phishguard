package com.phishguard.database;

import com.phishguard.utils.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * PhishGuard - LogDAO.java
 * -------------------------------------------------
 * Data Access Object for the 'logs' table.
 *
 * CRITICAL DESIGN RULE: LogDAO must NEVER throw any exception.
 * Logging failure must NEVER crash the application.
 * All exceptions are caught, printed to stderr, and swallowed.
 *
 * Usage:
 *   LogDAO.info("EMAIL_MONITOR", "Started polling inbox");
 *   LogDAO.warning("THREAT_DETECTED", "HIGH_RISK URL found");
 *   LogDAO.error("DB_CONNECTION", "Retry attempt 3");
 *   LogDAO.critical("SYSTEM", "Configuration missing");
 */
public final class LogDAO {

    private LogDAO() {}

    // ── Core write method ────────────────────────────────────────────────

    /**
     * Inserts a log entry into the logs table.
     * NEVER throws — any SQL/connection error is silently absorbed.
     *
     * @param eventType short category label (e.g., "EMAIL_MONITOR", "THREAT_DETECTED")
     * @param severity  one of: INFO, WARNING, ERROR, CRITICAL
     * @param details   human-readable detail message
     */
    public static void log(String eventType, String severity, String details) {
        String sql = "INSERT INTO " + Constants.TABLE_LOGS
                   + " (event_type, severity, details) VALUES (?, ?, ?)";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, eventType != null ? eventType : "UNKNOWN");
                ps.setString(2, severity  != null ? severity  : Constants.SEV_INFO);
                ps.setString(3, details   != null ? details   : "");
                ps.executeUpdate();
            }
        } catch (Exception e) {
            // Silently absorb — logging must never crash the app
            System.err.println("[LogDAO] Failed to write log: " + e.getMessage());
        }
    }

    // ── Convenience wrappers ─────────────────────────────────────────────

    /** Logs an INFO-level event. */
    public static void info(String eventType, String details) {
        log(eventType, Constants.SEV_INFO, details);
    }

    /** Logs a WARNING-level event. */
    public static void warning(String eventType, String details) {
        log(eventType, Constants.SEV_WARNING, details);
    }

    /** Logs an ERROR-level event. */
    public static void error(String eventType, String details) {
        log(eventType, Constants.SEV_ERROR, details);
    }

    /** Logs a CRITICAL-level event. */
    public static void critical(String eventType, String details) {
        log(eventType, Constants.SEV_CRITICAL, details);
    }

    // ── Read methods ─────────────────────────────────────────────────────

    /**
     * Retrieves the most recent log entries, newest first.
     *
     * @param limit maximum number of rows to return
     * @return List of String[4] arrays: {event_time, event_type, severity, details}
     *         Returns empty list on any error.
     */
    public static List<String[]> getRecentLogs(int limit) {
        List<String[]> results = new ArrayList<>();
        String sql = "SELECT event_time, event_type, severity, details "
                   + "FROM " + Constants.TABLE_LOGS
                   + " ORDER BY event_time DESC LIMIT ?";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        results.add(new String[]{
                            rs.getString("event_time"),
                            rs.getString("event_type"),
                            rs.getString("severity"),
                            rs.getString("details")
                        });
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[LogDAO] Failed to retrieve logs: " + e.getMessage());
        }
        return results;
    }

    /**
     * Returns the total number of log entries in the database.
     *
     * @return row count, or 0 on error
     */
    public static int getTotalLogCount() {
        String sql = "SELECT COUNT(*) FROM " + Constants.TABLE_LOGS;
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (Exception e) {
            System.err.println("[LogDAO] Failed to count logs: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Returns counts grouped by severity for the dashboard.
     * @return int[4]: {INFO count, WARNING count, ERROR count, CRITICAL count}
     */
    public static int[] getCountsBySeverity() {
        int[] counts = {0, 0, 0, 0};
        String[] levels = {
            Constants.SEV_INFO, Constants.SEV_WARNING,
            Constants.SEV_ERROR, Constants.SEV_CRITICAL
        };
        String sql = "SELECT COUNT(*) FROM " + Constants.TABLE_LOGS + " WHERE severity = ?";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            for (int i = 0; i < levels.length; i++) {
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, levels[i]);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) counts[i] = rs.getInt(1);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[LogDAO] Failed to get severity counts: " + e.getMessage());
        }
        return counts;
    }
}
