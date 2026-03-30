package com.phishguard.api;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

@WebSocket
public class WebSocketHandler {
    
    private static final Queue<Session> sessions = new ConcurrentLinkedQueue<>();
    
    @OnWebSocketConnect
    public void connected(Session session) {
        sessions.add(session);
    }
    
    @OnWebSocketClose
    public void closed(Session session, int statusCode, String reason) {
        sessions.remove(session);
    }
    
    @OnWebSocketMessage
    public void message(Session session, String message) {
        if (message.equals("ping")) {
            try {
                session.getRemote().sendString("pong");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void broadcastIncident(String email, String url, String decision, double score) {
        JSONObject obj = new JSONObject();
        obj.put("type", "NEW_INCIDENT");
        obj.put("email", email);
        obj.put("url", url);
        obj.put("decision", decision);
        obj.put("score", score);
        String msg = obj.toString();
        
        sessions.forEach(session -> {
            try {
                if (session.isOpen()) {
                    session.getRemote().sendString(msg);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }
}
