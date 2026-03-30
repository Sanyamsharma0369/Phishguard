package com.phishguard;

import com.phishguard.api.WebApiController;
import com.phishguard.database.DBConnection;
import com.phishguard.detection.AIModelEngine;
import com.phishguard.gui.MainWindow;
import com.phishguard.utils.ConfigLoader;

import javax.swing.*;

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

        // Step 5: Launch GUI
        System.out.println("[Main] Launching GUI...");
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            MainWindow window = new MainWindow();
            window.setVisible(true);
            System.out.println("[Main] ✓ GUI launched");
        });

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


