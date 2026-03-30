package com.phishguard.database;

import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * PhishGuard - IncidentDAO.java
 * -------------------------------------------------
 * Data Access Object for the 'incidents' table.
 *
 * Every URL that passes through the full detection pipeline is saved
 * as an incident, regardless of whether it is SAFE, SUSPICIOUS, or HIGH_RISK.
 * This provides a complete audit trail for forensic analysis.
 *
 * Usage:
 *   IncidentDAO.saveIncident(scorer);
 *   int total = IncidentDAO.getTotalIncidents();
 *   List<RiskScorer> recent = IncidentDAO.getRecentIncidents(50);
 */
public final class IncidentDAO {

    private IncidentDAO() {}

    // ── Write ─────────────────────────────────────────────────────────────

    /**
     * Persists a fully-analyzed RiskScorer to the incidents table.
     * All 5 layer scores, the final score, decision, and action are saved.
     *
     * @param scorer a RiskScorer that has been through DecisionEngine.decide()
     */
    public static void saveIncident(RiskScorer scorer) {
        if (scorer == null) {
            System.err.println("[IncidentDAO] Cannot save null scorer.");
            return;
        }

        String sql = "INSERT INTO " + Constants.TABLE_INCIDENTS + " ("
                   + "  email_sender, email_subject, url_found, "
                   + "  sender_score, text_score, ai_model_score, "
                   + "  threat_intel_score, visual_score, final_risk_score, "
                   + "  ai_decision, phishtank_confirmed, virustotal_detections, "
                   + "  visual_brand_detected, action_taken"
                   + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1,  scorer.emailSender);
                ps.setString(2,  scorer.emailSubject);
                ps.setString(3,  scorer.url);
                ps.setDouble(4,  scorer.senderScore);
                ps.setDouble(5,  scorer.textScore);
                ps.setDouble(6,  scorer.aiModelScore);
                ps.setDouble(7,  scorer.threatIntelScore);
                ps.setDouble(8,  scorer.visualScore);
                ps.setDouble(9,  scorer.finalScore);
                ps.setString(10, scorer.decision);
                ps.setBoolean(11, scorer.phishtankConfirmed);
                ps.setInt(12,   scorer.virusTotalDetections);
                ps.setString(13, scorer.visualBrandDetected);
                ps.setString(14, scorer.actionTaken);
                ps.executeUpdate();
            }

            System.out.println("[IncidentDAO] Saved: " + scorer.decision
                + " for " + scorer.url);

            // Also write a log entry for non-SAFE events
            if (!Constants.DECISION_SAFE.equals(scorer.decision)) {
                LogDAO.warning("INCIDENT_SAVED",
                    scorer.decision + " | " + scorer.url + " | score=" + scorer.finalScore);
            }

        } catch (Exception e) {
            System.err.println("[IncidentDAO] Error saving incident for "
                + scorer.url + ": " + e.getMessage());
            LogDAO.error("INCIDENT_SAVE_FAILED", e.getMessage());
        }
    }

    // ── Read ──────────────────────────────────────────────────────────────

    /**
     * Retrieves the most recent incidents, newest first.
     * Maps ResultSet rows back to lightweight RiskScorer objects.
     *
     * @param limit maximum number of rows to return
     * @return list of RiskScorer objects (only DB-populated fields are set)
     */
    public static List<RiskScorer> getRecentIncidents(int limit) {
        List<RiskScorer> incidents = new ArrayList<>();
        String sql = "SELECT * FROM " + Constants.TABLE_INCIDENTS
                   + " ORDER BY timestamp DESC LIMIT ?";
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        RiskScorer s = new RiskScorer(
                            rs.getString("url_found"),
                            rs.getString("email_sender"),
                            rs.getString("email_subject")
                        );
                        s.senderScore          = rs.getDouble("sender_score");
                        s.textScore            = rs.getDouble("text_score");
                        s.aiModelScore         = rs.getDouble("ai_model_score");
                        s.threatIntelScore     = rs.getDouble("threat_intel_score");
                        s.visualScore          = rs.getDouble("visual_score");
                        s.finalScore           = rs.getDouble("final_risk_score");
                        s.decision             = rs.getString("ai_decision");
                        s.phishtankConfirmed   = rs.getBoolean("phishtank_confirmed");
                        s.virusTotalDetections = rs.getInt("virustotal_detections");
                        s.visualBrandDetected  = rs.getString("visual_brand_detected");
                        s.actionTaken          = rs.getString("action_taken");
                        incidents.add(s);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[IncidentDAO] Error fetching incidents: " + e.getMessage());
        }
        return incidents;
    }

    /**
     * Returns the total number of incidents in the database.
     * @return total count, or 0 on error
     */
    public static int getTotalIncidents() {
        return countWhere("");
    }

    /**
     * Returns the number of incidents with a specific AI decision.
     * @param decision one of: SAFE, SUSPICIOUS, HIGH_RISK
     * @return count, or 0 on error
     */
    public static int getIncidentsByDecision(String decision) {
        return countWhere("WHERE ai_decision = '" + decision.replace("'", "''") + "'");
    }

    /**
     * Computes the average final_risk_score across all incidents.
     * @return average score (0.0–1.0), or 0.0 on error/empty table
     */
    public static double getAverageRiskScore() {
        String sql = "SELECT AVG(final_risk_score) FROM " + Constants.TABLE_INCIDENTS;
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    double avg = rs.getDouble(1);
                    return rs.wasNull() ? 0.0 : avg;
                }
            }
        } catch (Exception e) {
            System.err.println("[IncidentDAO] Error computing average: " + e.getMessage());
        }
        return 0.0;
    }

    /**
     * Returns today's incident counts for the daily_stats upsert (used by DashboardPanel).
     * @return int[3]: {total today, threats detected today, threats blocked today}
     */
    public static int[] getTodayCounts() {
        int[] counts = {0, 0, 0};
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            String sqlTotal = "SELECT COUNT(*) FROM " + Constants.TABLE_INCIDENTS
                            + " WHERE DATE(timestamp) = CURDATE()";
            try (PreparedStatement ps = conn.prepareStatement(sqlTotal);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) counts[0] = rs.getInt(1);
            }
            String sqlThreats = "SELECT COUNT(*) FROM " + Constants.TABLE_INCIDENTS
                              + " WHERE DATE(timestamp) = CURDATE() AND ai_decision != 'SAFE'";
            try (PreparedStatement ps = conn.prepareStatement(sqlThreats);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) counts[1] = rs.getInt(1);
            }
            String sqlBlocked = "SELECT COUNT(*) FROM " + Constants.TABLE_INCIDENTS
                              + " WHERE DATE(timestamp) = CURDATE() AND action_taken = 'BLOCKED'";
            try (PreparedStatement ps = conn.prepareStatement(sqlBlocked);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) counts[2] = rs.getInt(1);
            }
        } catch (Exception e) {
            System.err.println("[IncidentDAO] Error getting today's counts: " + e.getMessage());
        }
        return counts;
    }

    // ── Private helper ────────────────────────────────────────────────────

    private static int countWhere(String whereClause) {
        String sql = "SELECT COUNT(*) FROM " + Constants.TABLE_INCIDENTS
                   + (whereClause.isBlank() ? "" : " " + whereClause);
        try {
            Connection conn = DBConnection.getInstance().getConnection();
            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (Exception e) {
            System.err.println("[IncidentDAO] Count query failed: " + e.getMessage());
        }
        return 0;
    }
}
