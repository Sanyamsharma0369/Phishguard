package com.phishguard.monitor;

import com.phishguard.engine.RiskScorer;
import com.phishguard.websocket.NotificationServer;
import java.awt.*;
import java.awt.datatransfer.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * ClipboardMonitor - Automatically scans any URL copied to the Windows clipboard.
 * This extends PhishGuard's protection to desktop apps like WhatsApp, Telegram, and Discord.
 */
public class ClipboardMonitor {

    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
    );

    private String lastClipboard = "";
    private final ScheduledExecutorService scheduler = 
        Executors.newSingleThreadScheduledExecutor();

    public void start() {
        // Poll clipboard every 2 seconds
        scheduler.scheduleAtFixedRate(this::checkClipboard, 0, 2, TimeUnit.SECONDS);
        System.out.println("[Clipboard] Monitor started — watching for URLs...");
    }

    private void checkClipboard() {
        try {
            Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
            
            // Check if clipboard contains text
            if (!cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) return;
            
            String content = (String) cb.getData(DataFlavor.stringFlavor);

            if (content != null && !content.equals(lastClipboard)) {
                lastClipboard = content;
                Matcher m = URL_PATTERN.matcher(content);
                while (m.find()) {
                    String url = m.group();
                    System.out.println("[Clipboard] New URL detected: " + url);
                    scanUrl(url, "CLIPBOARD");
                }
            }
        } catch (Exception ignored) {
            // Likely clipboard busy by another process
        }
    }

    private void scanUrl(String url, String source) {
        // Run in background thread — don't block the clipboard polling loop
        CompletableFuture.runAsync(() -> {
            try {
                RiskScorer scorer = new RiskScorer(url, "clipboard-monitor");
                scorer.score(); // Full analysis pipeline

                System.out.printf("[Clipboard] Analysis: %s → %s (%.4f)%n",
                    url, scorer.decision, scorer.finalScore);

                // Fire WebSocket notification if threat detected
                if ("HIGH_RISK".equals(scorer.decision) || 
                    "SUSPICIOUS".equals(scorer.decision)) {
                    NotificationServer.getInstance().sendThreatAlert(
                        url, source, scorer.finalScore, scorer.decision
                    );
                }
            } catch (Exception e) {
                System.err.println("[Clipboard] Scan error: " + e.getMessage());
            }
        });
    }

    public void stop() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
        }
        System.out.println("[Clipboard] Monitor stopped.");
    }
}
