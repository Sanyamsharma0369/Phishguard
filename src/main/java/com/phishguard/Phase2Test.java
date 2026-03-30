package com.phishguard;

import com.phishguard.detection.AIModelEngine;
import com.phishguard.detection.URLFeatureExtractor;
import com.phishguard.engine.DecisionEngine;
import com.phishguard.engine.MitigationEngine;   // ← ADD THIS
import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.EntropyCalculator;

import java.util.Arrays;

public class Phase2Test {

    public static void main(String[] args) {
        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("  PhishGuard Phase 2 — Detection Engine Test");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();

        // ── 1. AIModelEngine ──────────────────────────────────────────
        System.out.println("--- [1] AI Model Engine ---");
        AIModelEngine.loadModels();
        System.out.println("[AIModel] Fallback mode: " + AIModelEngine.isFallbackMode());
        System.out.println();

        // ── 2. Shannon Entropy ────────────────────────────────────────
        System.out.println("--- [2] Shannon Entropy Calculator ---");
        EntropyCalculator.testAll();
        System.out.println();

        // ── 3. URL Feature Extraction ─────────────────────────────────
        System.out.println("--- [3] URL Feature Extractor ---");
        URLFeatureExtractor.testAll();
        System.out.println();

        // ── 4. Full Pipeline Tests ────────────────────────────────────
        System.out.println("--- [4] Full Detection Pipeline ---");
        String[] testCases = {
                "http://paypal-secure-verify-login.xyz/account/update",
                "https://www.google.com",
                "http://192.168.1.1/paypal/login/verify-account/confirm",
                "https://sbi-bank-alert.in/login?redirect=verify&id=838292"
        };

        for (String url : testCases) {
            try {
                double[] features = URLFeatureExtractor.extract(url);
                double aiScore    = AIModelEngine.predict(url);

                RiskScorer scorer = new RiskScorer(url, "attacker@evil.com", "Urgent Action Required");
                scorer.aiModelScore = aiScore;
                DecisionEngine.decide(scorer);

                System.out.printf("URL: %s%n", url);
                System.out.printf("  Features : %s%n", Arrays.toString(features));
                System.out.printf("  AI Score : %.4f%n", aiScore);
                System.out.printf("  Decision : %-12s | Final: %.4f%n", scorer.decision, scorer.finalScore);
                System.out.printf("  Reason   : %s%n%n", DecisionEngine.getDecisionReason(scorer));
            } catch (Exception e) {
                System.err.println("ERROR for " + url + ": " + e.getMessage());
            }
        }  // ← loop ends HERE

        // ── 5. MitigationEngine Tests ─────────────────────────────────
        System.out.println("--- [5] Mitigation Engine ---");

        RiskScorer testHighRisk = new RiskScorer(
                "http://paypal-verify.xyz/login",
                "attacker@scam.com",
                "Test Phishing"
        );
        testHighRisk.finalScore = 0.92;
        testHighRisk.decision   = "HIGH_RISK";
        MitigationEngine.mitigate(testHighRisk);

        RiskScorer testSuspicious = new RiskScorer(
                "http://bit.ly/click-here-now",
                "unknown@temp.com",
                "Test Suspicious"
        );
        testSuspicious.finalScore = 0.55;
        testSuspicious.decision   = "SUSPICIOUS";
        MitigationEngine.mitigate(testSuspicious);

        RiskScorer testSafe = new RiskScorer(
                "https://www.google.com",
                "friend@gmail.com",
                "Check this out"
        );
        testSafe.finalScore = 0.05;
        testSafe.decision   = "SAFE";
        MitigationEngine.mitigate(testSafe);

        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("  Phase 2 Test COMPLETE");
        System.out.println("═══════════════════════════════════════════════════════");
    }
}