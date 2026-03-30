package com.phishguard.gui;

import java.awt.*;

public class UITheme {
    // Colors
    public static final Color BG_PRIMARY    = new Color(13, 13, 26);
    public static final Color BG_SECONDARY  = new Color(20, 20, 40);
    public static final Color BG_CARD       = new Color(26, 26, 53);
    public static final Color ACCENT_CYAN   = new Color(0, 212, 255);
    public static final Color ACCENT_PURPLE = new Color(123, 47, 255);
    public static final Color SAFE_GREEN    = new Color(0, 255, 136);
    public static final Color WARN_ORANGE   = new Color(255, 136, 0);
    public static final Color DANGER_RED    = new Color(255, 34, 68);
    public static final Color TEXT_PRIMARY  = new Color(224, 230, 255);
    public static final Color TEXT_MUTED    = new Color(107, 125, 179);
    public static final Color BORDER_COLOR  = new Color(30, 45, 90);

    // Fonts
    public static final Font FONT_TITLE    = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_HEADING  = new Font("Segoe UI", Font.BOLD, 16);
    public static final Font FONT_BODY     = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_SMALL    = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO     = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_NUMBER   = new Font("Segoe UI", Font.BOLD, 38);

    // Helper: draw rounded rect card
    public static void drawCard(Graphics2D g2, int x, int y,
                                int w, int h, Color bg, Color border) {
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(bg);
        g2.fillRoundRect(x, y, w, h, 18, 18);
        g2.setColor(border);
        g2.setStroke(new BasicStroke(1f));
        g2.drawRoundRect(x, y, w, h, 18, 18);
    }

    // Helper: neon glow effect on text
    public static void drawGlowText(Graphics2D g2, String text,
                                    int x, int y, Font font, Color color) {
        g2.setFont(font);
        // Draw glow layers (blurred shadow)
        g2.setColor(new Color(color.getRed(), color.getGreen(),
                              color.getBlue(), 40));
        for (int i = 3; i >= 1; i--) {
            g2.drawString(text, x - i, y);
            g2.drawString(text, x + i, y);
            g2.drawString(text, x, y - i);
            g2.drawString(text, x, y + i);
        }
        g2.setColor(color);
        g2.drawString(text, x, y);
    }

    // Helper: animated pulse color (use with Timer)
    public static Color pulseColor(Color base, long startTime, int periodMs) {
        double elapsed = System.currentTimeMillis() - startTime;
        double phase = (elapsed % periodMs) / periodMs;
        float alpha = (float)(0.4 + 0.6 * Math.sin(phase * 2 * Math.PI));
        return new Color(base.getRed(), base.getGreen(),
                         base.getBlue(), (int)(alpha * 255));
    }
}
