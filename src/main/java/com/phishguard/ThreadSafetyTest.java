package com.phishguard;

import com.phishguard.detection.AIModelEngine;

public class ThreadSafetyTest {
    public static void main(String[] args) {
        try {
            System.out.println("=== PhishGuard AIModel 3-Test Diagnostic ===");
            AIModelEngine.loadModels();

            String testUrl = "http://paypal-secure-login.xyz/verify";
            
            for (int i = 1; i <= 3; i++) {
                System.out.println("\n--- RUN #" + i + " ---");
                double score = AIModelEngine.predict(testUrl);
                System.out.printf("RESULT: %.4f%n", score);
            }
            
            System.out.println("\nDiagnostic COMPLETE.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
