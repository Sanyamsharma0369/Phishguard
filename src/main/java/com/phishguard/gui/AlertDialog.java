package com.phishguard.gui;

import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.Constants;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public final class AlertDialog {

    private AlertDialog() {}

    public static void show(RiskScorer scorer) {
        if (scorer == null) return;
        boolean isHighRisk = Constants.DECISION_HIGH_RISK.equals(scorer.decision);
        
        Color themeColor = isHighRisk ? UITheme.DANGER_RED : UITheme.WARN_ORANGE;
        Color bgColor = isHighRisk ? new Color(26, 0, 8) : new Color(38, 20, 0);
        
        JDialog dialog = new JDialog();
        dialog.setUndecorated(true);
        dialog.setAlwaysOnTop(true);
        dialog.setModal(false);
        int h = isHighRisk ? 260 : 200;
        dialog.setSize(480, h);
        
        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        int finalX = screen.width - 500;
        int finalY = 20;
        dialog.setLocation(screen.width, finalY);

        JPanel root = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(bgColor);
                g2.fillRect(0, 0, getWidth(), getHeight());
                
                g2.setColor(themeColor);
                g2.fillRect(0, 0, 4, getHeight());
                
                g2.setColor(UITheme.BORDER_COLOR);
                g2.drawRect(0, 0, getWidth() - 1, getHeight() - 1);
            }
        };
        root.setOpaque(true);
        
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setOpaque(false);
        content.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        
        // TOP ROW
        JPanel topRow = new JPanel(new BorderLayout());
        topRow.setOpaque(false);
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        titlePanel.setOpaque(false);
        
        JPanel iconPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(themeColor);
                int[] xPoints = {10, 0, 20};
                int[] yPoints = {0, 18, 18};
                g2.fillPolygon(xPoints, yPoints, 3);
                g2.setColor(Color.WHITE);
                g2.setFont(new Font("Segoe UI", Font.BOLD, 12));
                g2.drawString("!", 8, 15);
            }
        };
        iconPanel.setPreferredSize(new Dimension(20, 20));
        iconPanel.setOpaque(false);
        titlePanel.add(iconPanel);
        
        JLabel titleLbl = new JLabel(isHighRisk ? "PHISHING BLOCKED" : "SUSPICIOUS URL");
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 15));
        titleLbl.setForeground(themeColor);
        titlePanel.add(titleLbl);
        
        JLabel closeBtn = new JLabel("✕");
        closeBtn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        closeBtn.setForeground(Color.GRAY);
        closeBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        closeBtn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) { closeBtn.setForeground(Color.RED); }
            public void mouseExited(MouseEvent e) { closeBtn.setForeground(Color.GRAY); }
            public void mouseClicked(MouseEvent e) { slideOut(dialog, screen.width); }
        });
        
        topRow.add(titlePanel, BorderLayout.WEST);
        topRow.add(closeBtn, BorderLayout.EAST);
        content.add(topRow);
        content.add(Box.createVerticalStrut(12));
        
        // URL ROW
        JPanel urlBox = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(20, 20, 20)); // Dark monospace box
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
            }
        };
        urlBox.setOpaque(false);
        urlBox.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        String urlString = scorer.url.length() > 60 ? scorer.url.substring(0, 57) + "..." : scorer.url;
        JLabel urlL = new JLabel(urlString);
        urlL.setFont(UITheme.FONT_MONO);
        urlL.setForeground(UITheme.ACCENT_CYAN);
        urlBox.add(urlL, BorderLayout.CENTER);
        content.add(urlBox);
        content.add(Box.createVerticalStrut(12));
        
        // SCORE ROW
        JPanel scoreRow = new JPanel(new BorderLayout());
        scoreRow.setOpaque(false);
        
        JPanel leftScore = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftScore.setOpaque(false);
        JLabel scrLbl = new JLabel("Risk Score: " + (int)(scorer.finalScore*100) + "%");
        scrLbl.setFont(UITheme.FONT_BODY);
        scrLbl.setForeground(UITheme.TEXT_PRIMARY);
        
        JProgressBar miniBar = new JProgressBar(0, 100);
        miniBar.setValue((int)(scorer.finalScore*100));
        miniBar.setForeground(themeColor);
        miniBar.setBackground(new Color(40, 40, 50));
        miniBar.setPreferredSize(new Dimension(80, 8));
        miniBar.setBorderPainted(false);
        
        leftScore.add(scrLbl);
        leftScore.add(miniBar);
        
        JLabel actionLbl = new JLabel(isHighRisk ? "Domain quarantined ✓" : "Flagged for review ⚠️");
        actionLbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        actionLbl.setForeground(themeColor);
        
        scoreRow.add(leftScore, BorderLayout.WEST);
        scoreRow.add(actionLbl, BorderLayout.EAST);
        content.add(scoreRow);
        content.add(Box.createVerticalStrut(16));
        
        // LAYER DOTS ROW
        JPanel dotsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        dotsRow.setOpaque(false);
        
        addLayerDot(dotsRow, "Sender", scorer.senderScore);
        addLayerDot(dotsRow, "NLP", scorer.textScore);
        addLayerDot(dotsRow, "AI Model", scorer.aiModelScore);
        addLayerDot(dotsRow, "Threat Intel", scorer.threatIntelScore);
        addLayerDot(dotsRow, "Visual", scorer.visualScore);
        
        content.add(dotsRow);
        content.add(Box.createVerticalStrut(20));
        
        // BUTTONS
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        btnPanel.setOpaque(false);
        
        JButton detBtn = new JButton("View Details");
        detBtn.setContentAreaFilled(false);
        detBtn.setForeground(UITheme.ACCENT_CYAN);
        detBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        detBtn.setBorder(BorderFactory.createLineBorder(UITheme.ACCENT_CYAN, 1));
        detBtn.setPreferredSize(new Dimension(100, 30));
        detBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        detBtn.addActionListener(e -> {
            JTextArea area = new JTextArea(scorer.getSummary() + "\n\n" + scorer.getDetailedBreakdown());
            area.setFont(UITheme.FONT_MONO);
            area.setBackground(UITheme.BG_PRIMARY);
            area.setForeground(UITheme.TEXT_PRIMARY);
            area.setEditable(false);
            JScrollPane sp = new JScrollPane(area);
            sp.setPreferredSize(new Dimension(500, 350));
            JOptionPane.showMessageDialog(dialog, sp, "Incident Details", JOptionPane.INFORMATION_MESSAGE);
        });
        
        JButton disBtn = new JButton("Dismiss");
        disBtn.setBackground(themeColor);
        disBtn.setForeground(Color.WHITE);
        disBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        disBtn.setBorderPainted(false);
        disBtn.setFocusPainted(false);
        disBtn.setPreferredSize(new Dimension(80, 30));
        disBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        disBtn.addActionListener(e -> slideOut(dialog, screen.width));
        
        btnPanel.add(detBtn);
        btnPanel.add(disBtn);
        content.add(btnPanel);
        
        root.add(content, BorderLayout.CENTER);
        
        // COUNTDOWN
        JProgressBar countdown = new JProgressBar(0, 300);
        countdown.setValue(300);
        countdown.setPreferredSize(new Dimension(480, 4));
        countdown.setBorderPainted(false);
        countdown.setForeground(themeColor);
        countdown.setBackground(UITheme.BG_PRIMARY);
        root.add(countdown, BorderLayout.SOUTH);
        
        dialog.setContentPane(root);
        dialog.setVisible(true);
        
        // Slide In Animation (15 steps)
        Timer slideIn = new Timer(20, null);
        int[] step = {0};
        slideIn.addActionListener(e -> {
            step[0]++;
            double t = step[0] / 15.0;
            double pct = 1.0 - Math.pow(1.0 - t, 3.0); 
            int x = (int)(screen.width - (500 * pct));
            dialog.setLocation(x, finalY);
            if(step[0] >= 15) {
                dialog.setLocation(finalX, finalY);
                slideIn.stop();
            }
        });
        slideIn.start();
        
        // Countdown Timer 30s
        Timer cdTimer = new Timer(100, null);
        int[] ticks = {300};
        cdTimer.addActionListener(e -> {
            ticks[0]--;
            countdown.setValue(ticks[0]);
            
            float ratio = ticks[0] / 300f;
            int r = (int)(themeColor.getRed() * ratio + 30 * (1-ratio));
            int gCol = (int)(themeColor.getGreen() * ratio + 30 * (1-ratio));
            int b = (int)(themeColor.getBlue() * ratio + 30 * (1-ratio));
            countdown.setForeground(new Color(r, gCol, b));
            
            if(ticks[0] <= 0) {
                cdTimer.stop();
                slideOut(dialog, screen.width);
            }
        });
        cdTimer.start();
        
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosed(java.awt.event.WindowEvent e) {
                cdTimer.stop();
                if (slideIn.isRunning()) slideIn.stop();
            }
        });
    }
    
    private static void slideOut(JDialog dialog, int screenWidth) {
        int startX = dialog.getX();
        Timer slide = new Timer(20, null);
        int[] step = {0};
        slide.addActionListener(e -> {
            step[0]++;
            int x = startX + (int)((screenWidth - startX) * (step[0]/15.0));
            dialog.setLocation(x, dialog.getY());
            if(step[0] >= 15) {
                slide.stop();
                dialog.dispose();
            }
        });
        slide.start();
    }
    
    private static void addLayerDot(JPanel parent, String name, double score) {
        JPanel dot = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color c = score >= 0.85 ? UITheme.DANGER_RED : (score >= 0.5 ? UITheme.WARN_ORANGE : UITheme.SAFE_GREEN);
                g2.setColor(c);
                g2.fillOval(0, 0, getWidth(), getHeight());
            }
        };
        dot.setPreferredSize(new Dimension(14, 14));
        dot.setOpaque(false);
        dot.setToolTipText(name + ": " + String.format("%.3f", score));
        parent.add(dot);
    }
}
