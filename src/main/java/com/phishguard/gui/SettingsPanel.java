package com.phishguard.gui;

import com.phishguard.utils.ConfigLoader;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Properties;

public class SettingsPanel extends JPanel {

    private MinimalSlider sliderHigh;
    private MinimalSlider sliderSuspicious;
    private MinimalSlider sliderPoll;

    private IOSSwitch toggleVisual;
    private IOSSwitch toggleThreat;
    private IOSSwitch toggleAutoMitigate;

    private JLabel lblStatus;

    public SettingsPanel() {
        setLayout(new BorderLayout());
        setBackground(UITheme.BG_PRIMARY);
        setBorder(BorderFactory.createEmptyBorder(40, 60, 40, 60));

        JLabel header = new JLabel("⚙ Settings & Configuration");
        header.setFont(UITheme.FONT_TITLE);
        header.setForeground(Color.WHITE);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 30, 0));
        add(header, BorderLayout.NORTH);

        JPanel grid = new JPanel(new GridLayout(1, 2, 40, 0));
        grid.setOpaque(false);

        grid.add(buildLeftColumn());
        grid.add(buildRightColumn());

        add(grid, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 0));
        bottom.setOpaque(false);
        bottom.setBorder(BorderFactory.createEmptyBorder(30, 0, 0, 0));

        lblStatus = new JLabel("");
        lblStatus.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        bottom.add(lblStatus);

        JButton saveBtn = createSaveButton();
        saveBtn.addActionListener(e -> saveSettings());
        bottom.add(saveBtn);

        add(bottom, BorderLayout.SOUTH);

        loadFromConfig();
    }

    private JPanel buildLeftColumn() {
        JPanel card = createCard("🧠 AI Confidence Thresholds");
        
        sliderHigh = new MinimalSlider(0.50, 1.00, 0.85, true);
        card.add(createLabeledControl("High Risk Threshold", sliderHigh));
        card.add(Box.createVerticalStrut(25));
        
        sliderSuspicious = new MinimalSlider(0.10, 0.80, 0.50, true);
        card.add(createLabeledControl("Suspicious Threshold", sliderSuspicious));
        card.add(Box.createVerticalStrut(25));
        
        sliderPoll = new MinimalSlider(10, 300, 60, false);
        card.add(createLabeledControl("Email Polling (seconds)", sliderPoll));

        return card;
    }

    private JPanel buildRightColumn() {
        JPanel card = createCard("⚙ System Settings");
        
        toggleVisual = new IOSSwitch(true);
        card.add(createLabeledControl("Enable Visual Core (CNN)", toggleVisual));
        card.add(Box.createVerticalStrut(35));
        
        toggleThreat = new IOSSwitch(true);
        card.add(createLabeledControl("Enable Threat Intel APIs", toggleThreat));
        card.add(Box.createVerticalStrut(35));
        
        toggleAutoMitigate = new IOSSwitch(false);
        card.add(createLabeledControl("Auto-Quarantine Threats", toggleAutoMitigate));

        return card;
    }

    private JPanel createCard(String title) {
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2.setColor(UITheme.BORDER_COLOR);
                g2.setStroke(new BasicStroke(1f));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
            }
        };
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLbl.setForeground(UITheme.ACCENT_CYAN);
        titleLbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(titleLbl);
        card.add(Box.createVerticalStrut(30));

        return card;
    }

    private JPanel createLabeledControl(String labelText, JComponent control) {
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(500, 40));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lbl = new JLabel(labelText);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 13));
        lbl.setForeground(UITheme.TEXT_MUTED);
        
        row.add(lbl, BorderLayout.NORTH);
        
        JPanel ctrlWrap = new JPanel(new BorderLayout());
        ctrlWrap.setOpaque(false);
        ctrlWrap.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        ctrlWrap.add(control, BorderLayout.CENTER);
        
        row.add(ctrlWrap, BorderLayout.CENTER);
        return row;
    }

    private JButton createSaveButton() {
        JButton btn = new JButton("💾 Save Settings") {
            private boolean hover = false;
            {
                addMouseListener(new MouseAdapter() {
                    public void mouseEntered(MouseEvent e) { hover = true; repaint(); }
                    public void mouseExited(MouseEvent e) { hover = false; repaint(); }
                });
            }
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                GradientPaint gp = new GradientPaint(0, 0, UITheme.ACCENT_CYAN, getWidth(), 0, new Color(0, 102, 170));
                if (hover) gp = new GradientPaint(0, 0, new Color(0, 255, 255), getWidth(), 0, UITheme.ACCENT_CYAN);
                g2.setPaint(gp);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                super.paintComponent(g);
            }
        };
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setForeground(Color.WHITE);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setPreferredSize(new Dimension(160, 40));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private void loadFromConfig() {
        ConfigLoader cfg = ConfigLoader.getInstance();
        
        double highT = cfg.getDouble("risk.threshold.high", 0.85);
        sliderHigh.setVal(highT);
        
        double suspT = cfg.getDouble("risk.threshold.suspicious", 0.50);
        sliderSuspicious.setVal(suspT);
        
        double pollS = cfg.getLong("poll.interval.ms", 60000L) / 1000.0;
        sliderPoll.setVal(pollS);

        toggleVisual.setOn(Boolean.parseBoolean(cfg.get("enable.visual.cnn", "true")));
        toggleThreat.setOn(Boolean.parseBoolean(cfg.get("enable.threat.intel", "true")));
        toggleAutoMitigate.setOn(Boolean.parseBoolean(cfg.get("auto.mitigate", "false")));
    }

    private void saveSettings() {
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception {
                try (InputStream in = ConfigLoader.class.getResourceAsStream("/config.properties")) {
                    Properties props = new Properties();
                    if (in != null) props.load(in);

                    props.setProperty("risk.threshold.high", String.format("%.2f", sliderHigh.getVal()));
                    props.setProperty("risk.threshold.suspicious", String.format("%.2f", sliderSuspicious.getVal()));
                    props.setProperty("poll.interval.ms", String.valueOf((long)(sliderPoll.getVal() * 1000)));
                    
                    props.setProperty("enable.visual.cnn", String.valueOf(toggleVisual.isOn()));
                    props.setProperty("enable.threat.intel", String.valueOf(toggleThreat.isOn()));
                    props.setProperty("auto.mitigate", String.valueOf(toggleAutoMitigate.isOn()));

                    try (FileOutputStream fos = new FileOutputStream("config.properties")) {
                        props.store(fos, "PhishGuard Settings — saved by GUI");
                    }
                }
                return null;
            }

            @Override protected void done() {
                try {
                    get();
                    lblStatus.setForeground(UITheme.SAFE_GREEN);
                    lblStatus.setText("✓ Settings saved successfully");
                    ConfigLoader.getInstance().reload();
                    
                    try {
                        Object[] options = {"OK"};
                        JOptionPane.showOptionDialog(SwingUtilities.getWindowAncestor(SettingsPanel.this),
                                "Configurations updated. Some changes may require a restart to take full effect.",
                                "Success", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
                                null, options, options[0]);
                    } catch (Exception ig) { }
                    
                } catch (Exception ex) {
                    lblStatus.setForeground(UITheme.DANGER_RED);
                    lblStatus.setText("✗ Save failed: " + ex.getMessage());
                }
            }
        }.execute();
    }

    // -- Custom Components --

    class MinimalSlider extends JPanel {
        private double min, max, val;
        private boolean isFloat;
        private boolean dragging = false;
        
        public MinimalSlider(double min, double max, double init, boolean isFloat) {
            this.min = min; this.max = max; this.val = init; this.isFloat = isFloat;
            setOpaque(false);
            setPreferredSize(new Dimension(300, 30));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            
            MouseAdapter ma = new MouseAdapter() {
                public void mousePressed(MouseEvent e) { dragging = true; updateVal(e.getX()); }
                public void mouseReleased(MouseEvent e) { dragging = false; }
                public void mouseDragged(MouseEvent e) { if(dragging) updateVal(e.getX()); }
            };
            addMouseListener(ma);
            addMouseMotionListener(ma);
        }
        
        public void setVal(double v) {
            this.val = Math.max(min, Math.min(max, v));
            repaint();
        }
        
        public double getVal() { return val; }
        
        private void updateVal(int x) {
            int trackW = getWidth() - 60;
            double p = Math.max(0, Math.min(1.0, (x - 10) / (double)trackW));
            val = min + p * (max - min);
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            int trackW = getWidth() - 60;
            int cy = getHeight() / 2;
            
            g2.setColor(UITheme.BORDER_COLOR);
            g2.fillRoundRect(10, cy - 4, trackW, 8, 8, 8);
            
            double p = (val - min) / (max - min);
            int fillW = (int)(p * trackW);
            
            if (fillW > 0) {
                GradientPaint gp = new GradientPaint(10, 0, UITheme.ACCENT_CYAN, 10 + fillW, 0, new Color(0, 102, 170));
                g2.setPaint(gp);
                g2.fillRoundRect(10, cy - 4, fillW, 8, 8, 8);
            }
            
            g2.setColor(Color.WHITE);
            g2.fillOval(10 + fillW - 8, cy - 8, 16, 16);
            
            g2.setFont(new Font("Consolas", Font.BOLD, 12));
            g2.setColor(UITheme.TEXT_PRIMARY);
            String txt = isFloat ? String.format("%.2f", val) : String.valueOf((int)val);
            g2.drawString(txt, getWidth() - 40, cy + 5);
        }
    }

    class IOSSwitch extends JPanel {
        private boolean on;
        private int animX;
        private Timer animTimer;
        
        public IOSSwitch(boolean initOn) {
            this.on = initOn;
            this.animX = on ? 22 : 2;
            setOpaque(false);
            setPreferredSize(new Dimension(80, 24));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            
            addMouseListener(new MouseAdapter() {
                public void mousePressed(MouseEvent e) {
                    on = !on;
                    animateToggle();
                }
            });
        }
        
        public void setOn(boolean b) { this.on = b; this.animX = on ? 22 : 2; repaint(); }
        public boolean isOn() { return on; }
        
        private void animateToggle() {
            int targetX = on ? 22 : 2;
            if (animTimer != null) animTimer.stop();
            animTimer = new Timer(15, e -> {
                if (animX < targetX) animX += 2;
                else if (animX > targetX) animX -= 2;
                
                if (Math.abs(animX - targetX) <= 2) {
                    animX = targetX;
                    animTimer.stop();
                }
                repaint();
            });
            animTimer.start();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            int w = 44;
            int h = 24;
            
            double p = (animX - 2) / 20.0;
            int r = (int)(UITheme.BORDER_COLOR.getRed() + p * (UITheme.SAFE_GREEN.getRed() - UITheme.BORDER_COLOR.getRed()));
            int gr = (int)(UITheme.BORDER_COLOR.getGreen() + p * (UITheme.SAFE_GREEN.getGreen() - UITheme.BORDER_COLOR.getGreen()));
            int b = (int)(UITheme.BORDER_COLOR.getBlue() + p * (UITheme.SAFE_GREEN.getBlue() - UITheme.BORDER_COLOR.getBlue()));
            
            g2.setColor(new Color(Math.max(0, Math.min(255, r)), Math.max(0, Math.min(255, gr)), Math.max(0, Math.min(255, b))));
            g2.fillRoundRect(0, 0, w, h, 24, 24);
            
            g2.setColor(Color.WHITE);
            g2.fillOval(animX, 2, 20, 20);
        }
    }
}
