package com.phishguard.engine;

import com.phishguard.utils.Constants;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * PhishGuard - RiskScorer.java
 * -------------------------------------------------
 * Data class (plain old Java object) that carries all 5 layer
 * analysis scores for a single URL analysis session, plus
 * metadata about the email and computed final values.
 *
 * Lifecycle:
 *  1. Instantiated by EmailMonitor / pipeline orchestrator
 *  2. Passed through each analyzer (SenderAnalyzer, TextNLPAnalyzer, etc.)
 *  3. Each analyzer sets its score field directly
 *  4. DecisionEngine calls calculateFinalScore() and sets decision + actionTaken
 *  5. IncidentDAO persists the RiskScorer to the database
 *
 * Design note: public fields are intentional for simplicity and readability
 * in this academic project. A production system would use setters/getters.
 */
public class RiskScorer {

    // ── Input metadata ──────────────────────────────────────────────────
    public String url;
    public String senderEmail;
    public String emailSubject;
    public LocalDateTime timestamp;

    // ── Layer scores (set by individual analyzer classes) ───────────────
    /** Layer 1: Sender reputation (0.0–1.0) — set by SenderAnalyzer */
    public double senderScore     = 0.0;
    /** Layer 2: Email text NLP (0.0–1.0) — set by TextNLPAnalyzer */
    public double textScore       = 0.0;
    /** Layer 3: URL AI Model ensemble (0.0–1.0) — set by AIModelEngine */
    public double aiModelScore    = 0.0;
    /** Layer 4: Live threat intelligence (0.0–1.0) — set by ThreatIntelChecker */
    public double threatIntelScore = 0.0;
    /** Layer 5: Visual CNN brand impersonation (0.0–1.0) — set by VisualAnalyzer */
    public double visualScore     = 0.0;

    // ── Computed outputs (set by DecisionEngine) ─────────────────────────
    public double finalScore = 0.0;
    public String decision   = Constants.DECISION_SAFE;    // SAFE | SUSPICIOUS | HIGH_RISK
    public String actionTaken    = Constants.ACTION_ALLOWED;  // ALLOWED | WARNED | BLOCKED
    /** Optional human-readable reason for the decision — set by DecisionEngine or MitigationEngine */
    public String decisionReason = null;

    // ── Threat intelligence detail (set by ThreatIntelChecker) ──────────
    public boolean phishtankConfirmed     = false;
    public int     virusTotalDetections   = 0;

    // ── Visual analysis detail (set by VisualAnalyzer) ──────────────────
    public String visualBrandDetected = null;
    public com.phishguard.utils.WhoisChecker.WhoisResult whoisResult = null;
    public String domainAge = null; // Human-readable age label for UI
    
    // ── Constructors ─────────────────────────────────────────────────────

    /**
     * Creates a new RiskScorer for a single URL analysis session.
     *
     * @param url          the URL being analyzed
     * @param emailSender  sender address of the containing email
     * @param emailSubject subject line of the containing email
     */
    public RiskScorer(String url, String senderEmail, String emailSubject) {
        this.url          = url;
        this.senderEmail  = senderEmail;
        this.emailSubject = emailSubject;
        this.timestamp    = LocalDateTime.now();
    }

    public RiskScorer(String url, String senderEmail) {
        this(url, senderEmail, "System/Manual Scan");
    }

    /**
     * Runs the full analysis pipeline for this URL.
     * Integrates AI model, Threat Intel, and Visual analysis.
     */
    public void score() {
        try {
            // Layer 3: AI model score
            this.aiModelScore = com.phishguard.detection.AIModelEngine.predict(url);
            
            // Layer 4: Threat Intel (only if suspicious)
            if (this.aiModelScore > 0.4) {
                this.threatIntelScore = com.phishguard.detection.ThreatIntelChecker.check(url);
            }
            
            // Layer 5: Visual analysis
            try {
                com.phishguard.detection.VisualAnalyzer.VisualResult vr = com.phishguard.detection.VisualAnalyzer.analyze(url);
                this.visualScore         = vr.score;
                this.visualBrandDetected = vr.detectedBrand;
            } catch (Exception e) {
                this.visualScore         = 0.0;
                this.visualBrandDetected = "Unknown";
            }
            
            // Decision & Mitigation
            com.phishguard.engine.DecisionEngine.decide(this);

            // Layer 6: WHOIS Domain Age (Zero-day protection)
            com.phishguard.utils.WhoisChecker.WhoisResult whois = com.phishguard.utils.WhoisChecker.check(url);
            this.whoisResult = whois;
            this.domainAge = (whois.ageDays() != -1) ? whois.ageLabel() : "Unknown";
            
            if (whois.ageDays() != -1) {
                this.finalScore = Math.min(1.0, Math.max(0.0, this.finalScore + whois.riskBonus()));
                // Re-run decision if WHOIS bonus pushes it over threshold
                com.phishguard.engine.DecisionEngine.decide(this);
            }

            com.phishguard.engine.MitigationEngine.mitigate(this);
            
        } catch (Exception e) {
            System.err.println("[RiskScorer] Critical error during analysis: " + e.getMessage());
            // Default to suspicious if engine fails to ensure safety
            this.decision = "SUSPICIOUS";
            this.actionTaken = "WARNED";
            this.decisionReason = "Analysis failed: " + e.getMessage();
        }
    }
    /**
     * Fast scan — only ML + Keywords, no network calls.
     * Used by extension popup for sub-second results.
     */
    public void scoreFast(String url, String sender, String source) {
        this.url = url;
        this.senderEmail = sender;
        try {
            // Layer 1: ML only
            this.aiModelScore = com.phishguard.detection.AIModelEngine.predict(url);
            
            // Layer 2: Keywords
            this.textScore = com.phishguard.detection.TextNLPAnalyzer.analyze(url + " " + sender);
            
            // Simple ensemble for quick scan (70% ML, 30% Keywords)
            this.finalScore = (this.aiModelScore * 0.7) + (this.textScore * 0.3);
            this.decision   = com.phishguard.engine.DecisionEngine.decide(this.finalScore);
            
            System.out.printf("[QuickScan] %s → %.4f (%s)%n", 
                url.substring(0, Math.min(50, url.length())), 
                finalScore, decision);
        } catch (Exception e) {
            this.finalScore = 0.0;
            this.decision   = "SAFE";
        }
    }

    // ── Core computation ─────────────────────────────────────────────────

    /**
     * Applies the weighted scoring formula to produce the final risk score.
     *
     * Formula (weights from Constants.java, must sum to 1.0):
     *   finalScore = (senderScore   × WEIGHT_SENDER)
     *              + (textScore     × WEIGHT_TEXT)
     *              + (aiModelScore  × WEIGHT_AI_MODEL)
     *              + (threatScore   × WEIGHT_THREAT_INTEL)
     *              + (visualScore   × WEIGHT_VISUAL)
     *
     * Result is clamped to [0.0, 1.0].
     *
     * Call this BEFORE reading finalScore.
     * DecisionEngine calls this automatically via decide().
     */
    public void calculateFinalScore() {
        finalScore = (senderScore    * Constants.WEIGHT_SENDER)
                   + (textScore      * Constants.WEIGHT_TEXT)
                   + (aiModelScore   * Constants.WEIGHT_AI_MODEL)
                   + (threatIntelScore * Constants.WEIGHT_THREAT_INTEL)
                   + (visualScore    * Constants.WEIGHT_VISUAL);

        // Count total active weight
        double totalWeight = 0;
        if (aiModelScore > 0)     { totalWeight += Constants.WEIGHT_AI_MODEL; }
        if (senderScore > 0)      { totalWeight += Constants.WEIGHT_SENDER; }
        if (textScore > 0)        { totalWeight += Constants.WEIGHT_TEXT; }
        if (threatIntelScore > 0) { totalWeight += Constants.WEIGHT_THREAT_INTEL; }
        if (visualScore > 0)      { totalWeight += Constants.WEIGHT_VISUAL; }

        // Normalize by actual active weight if not all layers fired
        if (totalWeight > 0 && totalWeight < 1.0) {
            finalScore = finalScore / totalWeight;
        }

        // Clamp to valid probability range
        finalScore = Math.max(0.0, Math.min(1.0, finalScore));
    }

    // ── Reporting helpers ────────────────────────────────────────────────

    /**
     * Returns a compact one-line summary for console logging.
     *
     * Example output:
     *   [2026-03-23 09:32] HIGH_RISK (0.912) | http://paypal-secure.xyz | from: attacker@evil.com
     *
     * @return formatted summary string
     */
    public String getSummary() {
        String ts = (timestamp != null)
            ? timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
            : "unknown-time";

        return String.format("[%s] %-12s (%.3f) | %s | from: %s",
            ts,
            decision,
            finalScore,
            url != null ? url : "N/A",
            senderEmail != null ? senderEmail : "unknown"
        );
    }

    /**
     * Returns a detailed multi-line breakdown for debug/report output.
     *
     * @return formatted multi-line string
     */
    public String getDetailedBreakdown() {
        return String.format(
            "╔═ Risk Analysis ══════════════════════════════════════╗%n" +
            "║ URL      : %-47s ║%n" +
            "║ From     : %-47s ║%n" +
            "║ Subject  : %-47s ║%n" +
            "╠═ Scores ════════════════════════════════════════════╣%n" +
            "║ Sender Reputation  (×%.2f): %-24.3f   ║%n" +
            "║ Text NLP           (×%.2f): %-24.3f   ║%n" +
            "║ AI Model           (×%.2f): %-24.3f   ║%n" +
            "║ Threat Intel       (×%.2f): %-24.3f   ║%n" +
            "║ Visual CNN         (×%.2f): %-24.3f   ║%n" +
            "╠═ Result ════════════════════════════════════════════╣%n" +
            "║ FINAL SCORE: %-39.4f   ║%n" +
            "║ DECISION   : %-39s   ║%n" +
            "║ ACTION     : %-39s   ║%n" +
            "╚═════════════════════════════════════════════════════╝",
            truncate(url, 47),
            truncate(senderEmail, 47),
            truncate(emailSubject, 47),
            Constants.WEIGHT_SENDER,    senderScore,
            Constants.WEIGHT_TEXT,      textScore,
            Constants.WEIGHT_AI_MODEL,  aiModelScore,
            Constants.WEIGHT_THREAT_INTEL, threatIntelScore,
            Constants.WEIGHT_VISUAL,    visualScore,
            finalScore,
            decision,
            actionTaken
        );
    }

    /** Truncates a string to at most maxLen characters, appending "..." if truncated. */
    private static String truncate(String s, int maxLen) {
        if (s == null) return "N/A";
        return s.length() <= maxLen ? s : s.substring(0, maxLen - 3) + "...";
    }

    @Override
    public String toString() {
        return getSummary();
    }
}
