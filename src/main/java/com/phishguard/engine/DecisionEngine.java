package com.phishguard.engine;

import com.phishguard.utils.ConfigLoader;
import com.phishguard.utils.Constants;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * PhishGuard - DecisionEngine.java
 * -------------------------------------------------
 * Applies the final risk classification rules to a populated RiskScorer.
 *
 * DECISION RULES (from config.properties, fallback to Constants defaults):
 *   finalScore >= risk.threshold.high       → HIGH_RISK → BLOCKED
 *   finalScore >= risk.threshold.suspicious → SUSPICIOUS → QUARANTINED/WARNED
 *   finalScore <  risk.threshold.suspicious → SAFE → ALLOWED
 *
 * This class is stateless — all methods are static.
 */
public final class DecisionEngine {

    private DecisionEngine() {}

    // ── Core classification ──────────────────────────────────────────────

    /**
     * Calculates the final risk score and assigns a decision + action to the scorer.
     *
     * Steps:
     *  1. Calls scorer.calculateFinalScore() to compute the weighted total.
     *  2. Reads thresholds from config.properties (with Constants fallbacks).
     *  3. Applies brand-spoofing override to effectiveScore (does NOT mutate finalScore).
     *  4. Sets scorer.decision and scorer.actionTaken accordingly.
     *  5. Returns the same scorer instance (for fluent chaining).
     *
     * @param scorer a RiskScorer with at least aiModelScore populated
     * @return the same scorer, now with decision and actionTaken set
     */
    public static RiskScorer decide(RiskScorer scorer) {
        if (scorer == null) {
            throw new IllegalArgumentException("[DecisionEngine] Cannot decide on a null RiskScorer.");
        }

        // Step 1: Compute weighted final score
        scorer.calculateFinalScore();

        // Step 2: Load thresholds from config (allows runtime override)
        ConfigLoader cfg = ConfigLoader.getInstance();
        double thresholdHigh = cfg.getDouble("risk.threshold.high",
                Constants.RISK_THRESHOLD_HIGH);
        double thresholdSusp = cfg.getDouble("risk.threshold.suspicious",
                Constants.RISK_THRESHOLD_SUSPICIOUS);

        // Step 3: Brand spoofing override
        double effectiveScore = scorer.finalScore;
        if (scorer.visualBrandDetected != null
                && !scorer.visualBrandDetected.isBlank()
                && !scorer.visualBrandDetected.equals("Unknown")) {
            effectiveScore = Math.max(effectiveScore, thresholdSusp + 0.01);
        }

        // Step 4: Classify based on effectiveScore
        if (effectiveScore >= thresholdHigh) {
            scorer.decision    = Constants.DECISION_HIGH_RISK;
            scorer.actionTaken = Constants.ACTION_BLOCKED;
            // AUTO-BLOCK: add to manual_blocks with auto flag
            autoBlock(scorer.url, scorer.senderEmail);

        } else if (effectiveScore >= thresholdSusp) {
            scorer.decision    = Constants.DECISION_SUSPICIOUS;
            scorer.actionTaken = Constants.ACTION_QUARANTINED;

        } else {
            scorer.decision    = Constants.DECISION_SAFE;
            scorer.actionTaken = Constants.ACTION_ALLOWED;
        }

        // Step 5: Log decision
        System.out.printf("[DecisionEngine] Score=%.4f → %-10s → %s%n",
                scorer.finalScore, scorer.decision, scorer.actionTaken);

        return scorer;
    }

    private static void autoBlock(String url, String sender) {
        try {
            // Extract domain and add to manual_blocks table
            String domain = new java.net.URL(url).getHost()
                .replaceFirst("^www\\.", "").toLowerCase();
            
            String sql = "INSERT IGNORE INTO manual_blocks (domain, reason, auto_blocked) VALUES (?, ?, ?)";
            try (Connection c = com.phishguard.database.DBConnection.getInstance().getConnection();
                 PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, domain);
                ps.setString(2, "AUTO: High risk score (sent by " + (sender != null ? sender : "unknown") + ")");
                ps.setInt(3, 1);
                ps.executeUpdate();
            }
            System.out.println("[AutoBlock] Domain blocked: " + domain);
        } catch (Exception e) {
            System.err.println("[AutoBlock] Error: " + e.getMessage());
        }
    }
    /**
     * Light classification: returns just the decision string based on a score.
     * Used by scoreFast() in RiskScorer for extension popup calls.
     */
    public static String decide(double score) {
        if (score >= 0.75) return Constants.DECISION_HIGH_RISK;
        if (score >= 0.40) return Constants.DECISION_SUSPICIOUS;
        return Constants.DECISION_SAFE;
    }

    // ── Human-readable explanation ───────────────────────────────────────

    /**
     * Returns a human-readable explanation of why a decision was reached.
     * Identifies the highest-contributing score and names it.
     *
     * Example output:
     *   "Primary trigger: AI Model (0.91) — URL structure matches high-risk phishing patterns."
     *
     * @param scorer a scorer that has already been through decide()
     * @return explanation string suitable for alert dialogs and PDF reports
     */
    public static String getDecisionReason(RiskScorer scorer) {
        if (scorer == null) return "No analysis data available.";
        if (scorer.decision == null) return "Decision has not been computed yet — call decide() first.";

        // Find the highest weighted contribution
        double[] weightedScores = {
                scorer.senderScore      * Constants.WEIGHT_SENDER,
                scorer.textScore        * Constants.WEIGHT_TEXT,
                scorer.aiModelScore     * Constants.WEIGHT_AI_MODEL,
                scorer.threatIntelScore * Constants.WEIGHT_THREAT_INTEL,
                scorer.visualScore      * Constants.WEIGHT_VISUAL
        };

        String[] layerNames = {
                "Sender Reputation",
                "Email Text (NLP)",
                "AI URL Model",
                "Threat Intelligence",
                "Visual CNN"
        };

        double[] rawScores = {
                scorer.senderScore,
                scorer.textScore,
                scorer.aiModelScore,
                scorer.threatIntelScore,
                scorer.visualScore
        };

        // Find which layer contributed the most to the final score
        int maxIdx = 0;
        for (int i = 1; i < weightedScores.length; i++) {
            if (weightedScores[i] > weightedScores[maxIdx]) {
                maxIdx = i;
            }
        }

        String primaryLayer = layerNames[maxIdx];
        double primaryScore = rawScores[maxIdx];

        String description = describeScore(maxIdx, primaryScore, scorer);
        return String.format("Primary trigger: %s (%.2f) — %s",
                primaryLayer, primaryScore, description);
    }

    /**
     * Generates a human-readable description for a specific layer's score.
     *
     * @param layerIndex index into the 5-layer array (0=Sender, 1=Text, 2=AI, 3=ThreatIntel, 4=Visual)
     * @param score      0.0–1.0 raw score for this layer
     * @param scorer     full scorer context for additional detail
     * @return short phrase describing why this layer scored high
     */
    private static String describeScore(int layerIndex, double score, RiskScorer scorer) {
        return switch (layerIndex) {
            case 0 -> score >= 0.7
                    ? "Sender domain appears suspicious or newly registered."
                    : "Sender analysis flagged minor anomalies.";
            case 1 -> score >= 0.7
                    ? "Email body contains multiple urgent/credential-related keywords."
                    : "Email text contains some phishing language patterns.";
            case 2 -> score >= 0.7
                    ? "URL structure matches high-risk phishing patterns (AI model)."
                    : "URL features partially match phishing patterns.";
            case 3 -> scorer.phishtankConfirmed
                    ? "URL confirmed as phishing by PhishTank database."
                    : String.format("VirusTotal flagged by %d engines.", scorer.virusTotalDetections);
            case 4 -> (scorer.visualBrandDetected != null && !scorer.visualBrandDetected.isBlank())
                    ? "Webpage visually impersonates brand: " + scorer.visualBrandDetected
                    : "Visual layout matches known phishing page templates.";
            default -> "Combined risk factors exceeded safe threshold.";
        };
    }

    // ── Batch utility ────────────────────────────────────────────────────

    /**
     * Returns a human-readable confidence label for a given risk score.
     * Used in the dashboard table, PDF report, and API responses.
     *
     * @param score 0.0–1.0 final risk score
     * @return confidence label string
     */
    public static String getConfidence(double score) {
        if (score >= 0.85) return "High Confidence";
        if (score >= 0.65) return "Medium Confidence";
        if (score >= 0.40) return "Low Confidence";
        return "Very Low Confidence";
    }

    /**
     * FOR UNIT TESTING ONLY.
     * Convenience method: creates a new RiskScorer with just an AI model score
     * and runs the full decision pipeline.
     *
     * @param url           the URL to evaluate
     * @param aiModelScore  pre-computed AI model score (0.0–1.0)
     * @return decided RiskScorer
     */
    public static RiskScorer quickDecide(String url, double aiModelScore) {
        RiskScorer scorer = new RiskScorer(url, "test@example.com", "Test");
        scorer.aiModelScore = aiModelScore;
        return decide(scorer);
    }
}