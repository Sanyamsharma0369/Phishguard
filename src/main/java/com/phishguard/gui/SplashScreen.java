package com.phishguard.gui;

import javax.swing.JWindow;
import javax.swing.Timer;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.Random;

public class SplashScreen extends JWindow {
    private int progress = 0;
    private String statusText = "Initializing...";
    private Timer bgTimer, typeTimer, fadeTimer;
    
    // Matrix rain
    private static final int COLS = 20;
    private int[] rainDrops = new int[COLS];
    private String chars = "01アイウエカサタナハ!@#$%^&*";
    private Random rand = new Random();
    
    // Logo fade
    private float logoAlpha = 0f;
    
    // Tagline typing
    private String fullTagline = "AI-Powered Phishing Mitigation System";
    private String currentTagline = "";
    private int typeIndex = 0;
    
    public SplashScreen() {
        setSize(700, 420);
        setLocationRelativeTo(null);
        setAlwaysOnTop(true);
        setBackground(UITheme.BG_PRIMARY);
        
        for (int i = 0; i < COLS; i++) {
            rainDrops[i] = rand.nextInt(420 / 15);
        }
        
        // Matrix rain timer
        bgTimer = new Timer(80, e -> {
            for (int i = 0; i < rainDrops.length; i++) {
                rainDrops[i]++;
                if (rainDrops[i] * 15 > getHeight() && Math.random() > 0.95) {
                    rainDrops[i] = 0;
                }
            }
            repaint();
        });
        bgTimer.start();
        
        // Logo fade in timer (over 1.5s = 1500ms)
        fadeTimer = new Timer(30, e -> {
            logoAlpha += 30f / 1500f;
            if (logoAlpha >= 1f) {
                logoAlpha = 1f;
                fadeTimer.stop();
            }
            repaint();
        });
        fadeTimer.start();
        
        // Typewriter timer
        typeTimer = new Timer(60, e -> {
            if (typeIndex < fullTagline.length()) {
                currentTagline += fullTagline.charAt(typeIndex);
                typeIndex++;
                repaint();
            } else {
                typeTimer.stop();
            }
        });
        typeTimer.start();
    }
    
    public void setProgress(int percent, String status) {
        this.progress = percent;
        this.statusText = status;
        repaint();
        
        if (percent >= 100) {
            Timer t = new Timer(400, e -> {
                bgTimer.stop();
                if (fadeTimer.isRunning()) fadeTimer.stop();
                if (typeTimer.isRunning()) typeTimer.stop();
                dispose();
            });
            t.setRepeats(false);
            t.start();
        }
    }
    
    @Override
    public void paint(Graphics g) {
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        // Background
        g2.setColor(UITheme.BG_PRIMARY);
        g2.fillRect(0, 0, getWidth(), getHeight());
        
        // Matrix rain
        g2.setFont(new Font("Consolas", Font.PLAIN, 15));
        int colWidth = getWidth() / COLS;
        for (int i = 0; i < COLS; i++) {
            int x = i * colWidth + (colWidth / 2);
            int maxY = rainDrops[i] * 15;
            for (int y = 0; y < maxY; y += 15) {
                float alpha = (float) y / maxY;
                if (alpha < 0) alpha = 0;
                if (alpha > 1) alpha = 1;
                g2.setColor(new Color(0, 255, 136, (int)(alpha * 200)));
                char c = chars.charAt(rand.nextInt(chars.length()));
                g2.drawString(String.valueOf(c), x, y);
            }
        }
        
        // Logo
        int cx = getWidth() / 2;
        int cy = getHeight() / 2 - 20;
        
        // Fade from BG_PRIMARY to ACCENT_CYAN
        int r = (int)(UITheme.BG_PRIMARY.getRed() + (UITheme.ACCENT_CYAN.getRed() - UITheme.BG_PRIMARY.getRed()) * logoAlpha);
        int gCol = (int)(UITheme.BG_PRIMARY.getGreen() + (UITheme.ACCENT_CYAN.getGreen() - UITheme.BG_PRIMARY.getGreen()) * logoAlpha);
        int b = (int)(UITheme.BG_PRIMARY.getBlue() + (UITheme.ACCENT_CYAN.getBlue() - UITheme.BG_PRIMARY.getBlue()) * logoAlpha);
        Color logoC = new Color(r, gCol, b);
        
        g2.setFont(new Font("Segoe UI", Font.BOLD, 42));
        FontMetrics fm = g2.getFontMetrics();
        String logoText = "PhishGuard";
        int lx = cx - fm.stringWidth(logoText) / 2;
        UITheme.drawGlowText(g2, logoText, lx, cy, new Font("Segoe UI", Font.BOLD, 42), logoC);
        
        // Tagline
        g2.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        fm = g2.getFontMetrics();
        int tx = cx - fm.stringWidth(fullTagline) / 2; // Center based on full so it doesn't jump
        g2.setColor(UITheme.TEXT_MUTED);
        g2.drawString(currentTagline, tx, cy + 30);
        
        // Progress bar background
        int barY = getHeight() - 40;
        g2.setColor(UITheme.BG_CARD);
        g2.fillRect(0, barY, getWidth(), 4);
        
        // Progress bar fill
        g2.setColor(UITheme.ACCENT_CYAN);
        int fillW = (int)((progress / 100f) * getWidth());
        g2.fillRect(0, barY, fillW, 4);
        
        // Glow on progress head
        if (fillW > 0) {
            g2.setColor(new Color(0, 212, 255, 100));
            g2.fillOval(fillW - 10, barY - 8, 20, 20);
        }
        
        // Status text
        g2.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        g2.setColor(UITheme.TEXT_MUTED);
        g2.drawString(statusText, 20, barY + 20);
    }
}
