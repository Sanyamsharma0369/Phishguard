package com.phishguard;

import com.phishguard.api.WebApiController;
import com.phishguard.database.DBConnection;
import com.phishguard.detection.AIModelEngine;
// Removed unused: import com.phishguard.gui.MainWindow;
import com.phishguard.utils.ConfigLoader;

// Removed unused: import javax.swing.*;

public class Main {

    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("   PhishGuard v1.0 - Starting Up...       ");
        System.out.println("===========================================");

        // Step 1: Load config
        try {
            ConfigLoader config = ConfigLoader.getInstance();
            if (!config.isLoaded()) {
                config.reload();
            }
            config.printSummary();
            System.out.println("[Main] ✓ Configuration loaded");
        } catch (Exception e) {
            System.err.println("[Main] ✗ Config error: " + e.getMessage());
        }

        // Step 2: Connect to database
        try {
            DBConnection db = DBConnection.getInstance();
            db.getConnection();
            System.out.println("[Main] ✓ Database connected");
        } catch (Exception e) {
            System.err.println("[Main] ✗ Database error: " + e.getMessage());
        }

        // Step 3: Load AI models
        try {
            AIModelEngine.loadModels();
            System.out.println("[Main] ✓ AI models loaded (fallback="
                    + AIModelEngine.isFallbackMode() + ")");
        } catch (Exception e) {
            System.err.println("[Main] ✗ AI model error: " + e.getMessage());
        }

        // Step 4: Start Web API (WebSocketHandler registers itself inside WebApiController)
        try {
            WebApiController.init();
            System.out.println("[Main] ✓ Web API running at http://localhost:8080");
        } catch (Exception e) {
            System.err.println("[Main] ✗ Web API error: " + e.getMessage());
        }

        // Step 5: Launch GUI (disabled per user request)
        System.out.println("[Main] GUI disabled. Web dashboard only.");
        /*
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            MainWindow window = new MainWindow();
            window.setVisible(true);
            System.out.println("[Main] ✓ GUI launched");
        });
        */

        // Start email monitoring in background thread
        new Thread(() -> {
            try {
                System.out.println("[Main] Starting email monitor...");
                new com.phishguard.email.EmailMonitor().run();  // ← FIXED
            } catch (Exception e) {
                System.err.println("[Main] Email monitor error: " + e.getMessage());
            }
        }, "EmailMonitor-Thread").start();



        System.out.println("[Main] PhishGuard is running!");
        System.out.println("[Main] Web Dashboard -> http://localhost:8080");
        System.out.println("[Main] Flask CNN API -> http://localhost:5000");

        // Keep main thread alive so Spark (daemon thread) doesn't die
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("[Main] Shutdown requested.");
        }
    }


}


