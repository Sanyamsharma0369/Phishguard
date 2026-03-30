package com.phishguard.engine;

import com.phishguard.database.IncidentDAO;
import com.phishguard.database.LogDAO;
import com.phishguard.database.QuarantineDAO;
import com.phishguard.email.URLExtractor;

/**
 * PhishGuard - MitigationEngine.java
 * -------------------------------------------------
 * Applies the appropriate mitigation action based on the AI decision.
 *
 * Decision → Action mapping:
 *   HIGH_RISK   → Quarantine domain + save incident + log CRITICAL + console alert
 *   SUSPICIOUS  → Save incident + log WARNING + console warning
 *   SAFE        → Log INFO only + console confirmation
 *
 * GUI alert dialogs (Swing JOptionPane) will be added in Phase 6.
 * This class intentionally does NOT import any Swing classes.
 */
public final class MitigationEngine {

    private MitigationEngine() {}

    // ── Public entry point ────────────────────────────────────────────────

    /**
     * Routes the scored URL to the appropriate handler based on the AI decision.
     * All handlers are safe — no exception can propagate out of this method.
     *
     * @param scorer a fully-decided RiskScorer (DecisionEngine.decide() already called)
     */
    public static void mitigate(RiskScorer scorer) {
        if (scorer == null) return;

        try {
            switch (scorer.decision) {
                case "HIGH_RISK":
                    handleHighRisk(scorer);
                    break;
                case "SUSPICIOUS":
                    handleSuspicious(scorer);
                    break;
                default:
                    handleSafe(scorer);
                    break;
            }
        } catch (Exception e) {
            System.err.println("[MitigationEngine] Unhandled error: " + e.getMessage());
            LogDAO.error("MITIGATION_ERROR", e.getMessage());
        }
    }

    // ── Decision handlers ─────────────────────────────────────────────────

    /**
     * HIGH_RISK handler:
     *   1. Quarantine the sending domain to block future emails automatically
     *   2. Save the full incident to the incidents table
     *   3. Log CRITICAL event
     *   4. Print prominent console alert (GUI dialog in Phase 6)
     */
    private static void handleHighRisk(RiskScorer scorer) {
        // 1. Extract and quarantine the domain
        String domain = URLExtractor.extractDomain(scorer.url);
        if (!domain.isBlank()) {
            String reason = "Auto-quarantined: finalScore="
                + String.format("%.4f", scorer.finalScore);
            QuarantineDAO.addDomain(domain, reason);
        }

        // 2. Save full incident record
        scorer.actionTaken = "BLOCKED";
        IncidentDAO.saveIncident(scorer);

        // 3. Log CRITICAL
        LogDAO.critical("PHISHING_BLOCKED",
            "URL: " + scorer.url + " | Score: " + String.format("%.4f", scorer.finalScore));

        // 4. Console alert (Phase 6 will add JOptionPane dialog here)
        System.out.println("🚫 [BLOCKED] HIGH RISK URL: " + scorer.url);
        System.out.println("   Risk Score : " + String.format("%.4f", scorer.finalScore));
        System.out.println("   Domain quarantined: " + domain);
    }

    /**
     * SUSPICIOUS handler:
     *   1. Save incident to DB
     *   2. Log WARNING
     *   3. Print warning to console (GUI warning notification in Phase 6)
     */
    private static void handleSuspicious(RiskScorer scorer) {
        scorer.actionTaken = "WARNED";
        IncidentDAO.saveIncident(scorer);

        LogDAO.warning("SUSPICIOUS_URL",
            "URL: " + scorer.url + " | Score: " + String.format("%.4f", scorer.finalScore));

        System.out.println("⚠️  [WARNED] SUSPICIOUS URL: " + scorer.url);
        System.out.println("   Risk Score : " + String.format("%.4f", scorer.finalScore));
        // Phase 6: AlertDialog.showWarning(scorer);
    }

    /**
     * SAFE handler:
     *   1. Log INFO (no DB incident for safe URLs — keeps incidents table focused)
     *   2. Print confirmation to console
     */
    private static void handleSafe(RiskScorer scorer) {
        scorer.actionTaken = "ALLOWED";
        LogDAO.info("URL_ALLOWED",
            "URL: " + scorer.url + " | Score: " + String.format("%.4f", scorer.finalScore));

        System.out.println("✅ [ALLOWED] SAFE URL: " + scorer.url);
    }
}
