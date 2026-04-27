package com.phishguard.websocket;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import com.google.gson.Gson;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class NotificationServer extends WebSocketServer {

    private static NotificationServer instance;
    private static final int WS_PORT = 8081;
    private static final Gson GSON = new Gson();

    // All connected dashboard clients
    private final Set<WebSocket> clients = ConcurrentHashMap.newKeySet();

    private NotificationServer() {
        super(new InetSocketAddress(WS_PORT));
        setReuseAddr(true);
    }

    public static NotificationServer getInstance() {
        if (instance == null) {
            instance = new NotificationServer();
        }
        return instance;
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        clients.add(conn);
        System.out.println("[WS] Client connected: " + conn.getRemoteSocketAddress()
            + " | Total: " + clients.size());

        // Send welcome ping
        conn.send(GSON.toJson(Map.of(
            "type", "CONNECTED",
            "message", "PhishGuard WebSocket connected ✅",
            "timestamp", System.currentTimeMillis()
        )));
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        clients.remove(conn);
        System.out.println("[WS] Client disconnected | Remaining: " + clients.size());
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        // Dashboard can send ping to keep alive
        if ("PING".equals(message)) {
            conn.send("{\"type\":\"PONG\"}");
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.err.println("[WS] Error: " + ex.getMessage());
        if (conn != null) clients.remove(conn);
    }

    @Override
    public void onStart() {
        System.out.println("[WS] NotificationServer started on port " + WS_PORT);
    }

    // ── Broadcast to ALL connected dashboards ────────────────────────────────
    public void broadcast(Map<String, Object> payload) {
        if (clients.isEmpty()) return;
        String json = GSON.toJson(payload);
        clients.removeIf(c -> !c.isOpen()); // clean dead connections
        clients.forEach(c -> {
            try { c.send(json); }
            catch (Exception e) { System.err.println("[WS] Send failed: " + e.getMessage()); }
        });
        System.out.println("[WS] Broadcast to " + clients.size() + " client(s): " + payload.get("type"));
    }

    // ── Convenience methods ──────────────────────────────────────────────────
    public void sendThreatAlert(String url, String sender, double score, String decision) {
        broadcast(Map.of(
            "type",      "THREAT_ALERT",
            "url",       url,
            "sender",    sender != null ? sender : "Unknown",
            "score",     String.format("%.4f", score),
            "decision",  decision,
            "timestamp", System.currentTimeMillis()
        ));
    }

    public void sendNewIncident(String url, String decision, double score) {
        broadcast(Map.of(
            "type",      "NEW_INCIDENT",
            "url",       url,
            "decision",  decision,
            "score",     String.format("%.4f", score),
            "timestamp", System.currentTimeMillis()
        ));
    }

    public void sendStats(int total, int threats, int blocked) {
        broadcast(Map.of(
            "type",    "STATS_UPDATE",
            "total",   total,
            "threats", threats,
            "blocked", blocked
        ));
    }

    public int getConnectedCount() {
        return clients.size();
    }
}
