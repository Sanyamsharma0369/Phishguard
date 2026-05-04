package com.phishguard;

import com.phishguard.api.WebApiController;
import com.phishguard.database.DBConnection;
import com.phishguard.detection.AIModelEngine;
// Removed unused: import com.phishguard.gui.MainWindow;
import com.phishguard.utils.ConfigLoader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

// Removed unused: import javax.swing.*;

public class Main {

    private static Process flaskProcess = null;

    public static void startFlaskService() {
        // First check if Flask is already running
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:5000/health"))
                .timeout(Duration.ofSeconds(2))
                .GET().build();
            int status = HttpClient.newHttpClient()
                .send(req, HttpResponse.BodyHandlers.ofString())
                .statusCode();
            if (status == 200) {
                System.out.println("[Flask] Already running on port 5000");
                return;
            }
        } catch (Exception ignored) {}

        // Not running — start it
        System.out.println("[Flask] Starting CNN service...");
        try {
            // Detect python command (python3 on Mac/Linux, python on Windows)
            String pythonCmd = System.getProperty("os.name")
                .toLowerCase().contains("win") ? "python" : "python3";

            // Path to your Flask app — adjust if needed
            String flaskPath = "python_service/app.py";

            ProcessBuilder pb = new ProcessBuilder(pythonCmd, flaskPath);
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.INHERIT); // Show Flask logs in IntelliJ
            flaskProcess = pb.start();

            // Wait up to 10 seconds for Flask to be ready
            System.out.println("[Flask] Waiting for CNN service to start...");
            for (int i = 0; i < 10; i++) {
                Thread.sleep(1000);
                try {
                    HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:5000/health"))
                        .timeout(Duration.ofSeconds(1))
                        .GET().build();
                    int status = HttpClient.newHttpClient()
                        .send(req, HttpResponse.BodyHandlers.ofString())
                        .statusCode();
                    if (status == 200) {
                        System.out.println("[Flask] CNN service started successfully!");
                        return;
                    }
                } catch (Exception ignored) {}
                System.out.println("[Flask] Waiting... (" + (i + 1) + "/10)");
            }
            System.out.println("[Flask] CNN service slow to start - continuing anyway.");

        } catch (Exception e) {
            System.err.println("[Flask] Could not start CNN service: " + e.getMessage());
            System.err.println("[Flask] Start manually: cd python_service && python app.py");
        }
    }

    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("   PhishGuard v1.0 - Starting Up...       ");
        System.out.println("===========================================");

        // Step 0: Auto-start Flask CNN
        startFlaskService();

        // Step 1: Load config
        try {
            ConfigLoader config = ConfigLoader.getInstance();
            if (!config.isLoaded()) {
                config.reload();
            }
            config.printSummary();
            System.out.println("[Main] Configuration loaded");
        } catch (Exception e) {
            System.err.println("[Main] Config error: " + e.getMessage());
        }

        // Step 2: Connect to database
        try {
            DBConnection db = DBConnection.getInstance();
            db.getConnection();
            System.out.println("[Main] Database connected");
            com.phishguard.utils.ThreatIntelCache.purgeExpired();
            System.out.println("[Cache] Threat Intel Cache initialized.");
        } catch (Exception e) {
            System.err.println("[Main] Database error: " + e.getMessage());
        }

        // Step 3: Load AI models
        try {
            AIModelEngine.loadModels();
            System.out.println("[Main] AI models loaded (fallback="
                    + AIModelEngine.isFallbackMode() + ")");
        } catch (Exception e) {
            System.err.println("[Main] AI model error: " + e.getMessage());
        }

        // ── Start WebSocket Notification Server ──────────────────────────────────
        try {
            com.phishguard.websocket.NotificationServer wsServer = com.phishguard.websocket.NotificationServer.getInstance();
            wsServer.start();
            System.out.println("[Main] WebSocket server running on ws://localhost:8081");

            // Shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("[Shutdown] Stopping PhishGuard...");
                try { wsServer.stop(); }
                catch (Exception e) { e.printStackTrace(); }

                if (flaskProcess != null && flaskProcess.isAlive()) {
                    flaskProcess.destroy();
                    System.out.println("[Flask] CNN service stopped.");
                }
            }));
        } catch (Exception e) {
            System.err.println("[Main] WebSocket error: " + e.getMessage());
        }

        // Step 4: Start Web API (WebSocketHandler registers itself inside WebApiController)
        try {
            WebApiController.init();
            System.out.println("[Main] Web API running at http://localhost:8080");
        } catch (Exception e) {
            System.err.println("[Main] Web API error: " + e.getMessage());
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
            System.out.println("[Main] GUI launched");
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

        // ── Start Clipboard Monitor ──────────────────────────────────────────
        try {
            com.phishguard.monitor.ClipboardMonitor cm = new com.phishguard.monitor.ClipboardMonitor();
            cm.start();
            Runtime.getRuntime().addShutdownHook(new Thread(cm::stop));
        } catch (Exception e) {
            System.err.println("[Main] Clipboard monitor error: " + e.getMessage());
        }

        // Keep main thread alive so Spark (daemon thread) doesn't die
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("[Main] Shutdown requested.");
        }
    }


}


