package com.phishguard.gui;

import com.phishguard.detection.AIModelEngine;
import com.phishguard.detection.ThreatIntelChecker;
import com.phishguard.detection.VisualAnalyzer;
import com.phishguard.engine.DecisionEngine;
import com.phishguard.engine.MitigationEngine;
import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.Constants;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class ScannerPanel extends JPanel {

    private JTextField urlInput;
    private ScanButton scanBtn;
    
    // PROGRESS
    private JPanel progressRow;
    private StepIndicator[] steps;
    private Timer progressSimTimer;
    
    // RESULTS
    private JPanel resultsPanel;
    private JPanel breakdownContainer;
    private BannerPanel decisionBanner;
    private ScoreGauge scoreGauge;

    public ScannerPanel() {
        setLayout(new BorderLayout());
        setBackground(UITheme.BG_PRIMARY);
        
        JPanel mainCol = new JPanel(new BorderLayout(0, 20));
        mainCol.setBackground(UITheme.BG_PRIMARY);
        mainCol.setBorder(BorderFactory.createEmptyBorder(24, 40, 40, 40));
        
        mainCol.add(buildTopSection(), BorderLayout.NORTH);
        mainCol.add(buildResultsSection(), BorderLayout.CENTER);
        
        JScrollPane sp = new JScrollPane(mainCol);
        sp.setBorder(null);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        add(sp, BorderLayout.CENTER);
    }

    private JPanel buildTopSection() {
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setOpaque(false);

        JLabel header = new JLabel("🔍 URL Security Scanner");
        header.setFont(UITheme.FONT_TITLE);
        header.setForeground(Color.WHITE);
        header.setAlignmentX(Component.CENTER_ALIGNMENT);
        top.add(header);
        top.add(Box.createVerticalStrut(6));

        JLabel sub = new JLabel("Real-time analysis through 5 AI detection layers");
        sub.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        sub.setForeground(UITheme.TEXT_MUTED);
        sub.setAlignmentX(Component.CENTER_ALIGNMENT);
        top.add(sub);
        top.add(Box.createVerticalStrut(24));

        JPanel inputRowBox = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_CARD);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
                g2.setColor(UITheme.BORDER_COLOR);
                g2.setStroke(new BasicStroke(1f));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
            }
        };
        inputRowBox.setOpaque(false);
        inputRowBox.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        urlInput = new JTextField(40) {
            private boolean glow = false;
            {
                addFocusListener(new java.awt.event.FocusAdapter() {
                    public void focusGained(java.awt.event.FocusEvent e) { glow = true; repaint(); }
                    public void focusLost(java.awt.event.FocusEvent e) { glow = false; repaint(); }
                });
            }
            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(glow ? UITheme.ACCENT_CYAN : UITheme.BORDER_COLOR);
                g2.setStroke(new BasicStroke(glow ? 2f : 1f));
                g2.drawRoundRect(1, 1, getWidth() - 3, getHeight() - 3, 8, 8);
                g2.dispose();
            }
        };
        urlInput.setFont(new Font("Consolas", Font.PLAIN, 13));
        urlInput.setBackground(UITheme.BG_PRIMARY);
        urlInput.setForeground(UITheme.TEXT_PRIMARY);
        urlInput.setCaretColor(UITheme.ACCENT_CYAN);
        urlInput.putClientProperty("JTextField.placeholderText", "https://example.com");
        urlInput.setPreferredSize(new Dimension(500, 42));
        urlInput.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        urlInput.addActionListener(e -> startScan());

        scanBtn = new ScanButton("⚡ Analyze");
        scanBtn.addActionListener(e -> startScan());
        
        JPanel iw = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 0));
        iw.setOpaque(false);
        iw.add(urlInput);
        iw.add(scanBtn);
        inputRowBox.add(iw);
        
        top.add(inputRowBox);
        top.add(Box.createVerticalStrut(24));

        progressRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        progressRow.setOpaque(false);
        progressRow.setVisible(false);
        
        String[] layerNames = {"Sender", "Text NLP", "AI Model", "Threat Intel", "Visual CNN"};
        String[] emojis = {"📩", "📝", "🤖", "🌐", "👁"};
        steps = new StepIndicator[5];
        for (int i = 0; i < 5; i++) {
            steps[i] = new StepIndicator(emojis[i], layerNames[i]);
            progressRow.add(steps[i]);
        }
        
        top.add(progressRow);
        return top;
    }

    private JPanel buildResultsSection() {
        resultsPanel = new JPanel(new BorderLayout(0, 20));
        resultsPanel.setOpaque(false);
        resultsPanel.setVisible(false);

        breakdownContainer = new JPanel();
        breakdownContainer.setLayout(new BoxLayout(breakdownContainer, BoxLayout.Y_AXIS));
        breakdownContainer.setOpaque(false);
        
        JPanel breakWrapper = new JPanel(new BorderLayout());
        breakWrapper.setOpaque(false);
        breakWrapper.add(breakdownContainer, BorderLayout.CENTER);

        decisionBanner = new BannerPanel();
        
        scoreGauge = new ScoreGauge();
        JPanel gaugeWrap = new JPanel(new FlowLayout(FlowLayout.CENTER));
        gaugeWrap.setOpaque(false);
        gaugeWrap.add(scoreGauge);

        JPanel bottomGroup = new JPanel(new BorderLayout(0, 20));
        bottomGroup.setOpaque(false);
        bottomGroup.add(decisionBanner, BorderLayout.NORTH);
        bottomGroup.add(gaugeWrap, BorderLayout.CENTER);

        resultsPanel.add(breakWrapper, BorderLayout.CENTER);
        resultsPanel.add(bottomGroup, BorderLayout.SOUTH);

        return resultsPanel;
    }

    private void startScan() {
        String raw = urlInput.getText().trim();
        if (raw.isBlank()) return;
        if (!raw.startsWith("http")) { raw = "http://" + raw; urlInput.setText(raw); }
        final String url = raw;

        scanBtn.setLoading(true);
        resultsPanel.setVisible(false);
        breakdownContainer.removeAll();
        
        for (StepIndicator s : steps) s.setWaiting();
        progressRow.setVisible(true);

        progressSimTimer = new Timer(600, null);
        int[] stepIdx = {0};
        progressSimTimer.addActionListener(e -> {
            if (stepIdx[0] > 0 && stepIdx[0] <= 5) steps[stepIdx[0]-1].setDone(0.0);
            if (stepIdx[0] < 5) steps[stepIdx[0]].setActive();
            stepIdx[0]++;
            if (stepIdx[0] > 5) progressSimTimer.stop();
        });
        progressSimTimer.start();

        new SwingWorker<RiskScorer, Void>() {
            @Override
            protected RiskScorer doInBackground() throws Exception {
                RiskScorer scorer = new RiskScorer(url, "manual-scan", "Manual Scan");
                scorer.senderScore  = 0.0;
                scorer.textScore    = 0.0;
                scorer.aiModelScore = AIModelEngine.predict(url);
                if (scorer.aiModelScore > 0.4) scorer.threatIntelScore = ThreatIntelChecker.check(url);
                VisualAnalyzer.VisualResult vr = VisualAnalyzer.analyze(url);
                scorer.visualScore = vr.score;
                scorer.visualBrandDetected = vr.detectedBrand;
                DecisionEngine.decide(scorer);
                MitigationEngine.mitigate(scorer);
                return scorer;
            }

            @Override
            protected void done() {
                scanBtn.setLoading(false);
                if (progressSimTimer != null) progressSimTimer.stop();
                
                try {
                    RiskScorer result = get();
                    steps[0].setDone(result.senderScore);
                    steps[1].setDone(result.textScore);
                    steps[2].setDone(result.aiModelScore);
                    steps[3].setDone(result.threatIntelScore);
                    steps[4].setDone(result.visualScore);
                    displayResults(result);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }.execute();
    }

    private void displayResults(RiskScorer scorer) {
        progressRow.setVisible(false);
        resultsPanel.setVisible(true);
        
        breakdownContainer.removeAll();
        addBreakdownRow("🔍 Sender Analysis", scorer.senderScore);
        addBreakdownRow("📝 Text NLP", scorer.textScore);
        addBreakdownRow("🤖 AI Model", scorer.aiModelScore);
        addBreakdownRow("🌐 Threat Intel", scorer.threatIntelScore);
        addBreakdownRow("👁 Visual CNN", scorer.visualScore);
        
        scoreGauge.setScore(scorer.finalScore);
        
        if (Constants.DECISION_HIGH_RISK.equals(scorer.decision)) {
            decisionBanner.setInfo("🚫  BLOCKED — URL quarantined automatically", UITheme.DANGER_RED, new Color(45, 0, 8), new Color(61, 0, 16));
        } else if (Constants.DECISION_SUSPICIOUS.equals(scorer.decision)) {
            decisionBanner.setInfo("⚠️  SUSPICIOUS — Proceed with caution", UITheme.WARN_ORANGE, new Color(45, 26, 0), new Color(61, 37, 0));
        } else {
            decisionBanner.setInfo("✅  SAFE — No threats detected", UITheme.SAFE_GREEN, new Color(0, 26, 13), new Color(0, 51, 25));
        }

        resultsPanel.setLocation(resultsPanel.getX(), 40);
        Animator.fadeIn(resultsPanel, 300);
        Animator.slideUp(resultsPanel, 40, 0, 300);
    }
    
    private void addBreakdownRow(String name, double sc) {
        JPanel row = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.setColor(UITheme.BORDER_COLOR);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
            }
        };
        row.setOpaque(false);
        row.setPreferredSize(new Dimension(800, 40));
        row.setMaximumSize(new Dimension(800, 40));
        row.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 16));
        
        JLabel nL = new JLabel(name);
        nL.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        nL.setForeground(UITheme.TEXT_PRIMARY);
        nL.setPreferredSize(new Dimension(200, 40));
        
        JPanel barP = new JPanel() {
            private int fillW = 0;
            {
                Animator.countUp(0, (int)(sc * 250), 600, w -> { fillW = w; repaint(); });
            }
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int y = (getHeight() - 8) / 2;
                g2.setColor(UITheme.BORDER_COLOR);
                g2.fillRoundRect(0, y, 250, 8, 8, 8);
                
                Color c = sc >= 0.85 ? UITheme.DANGER_RED : (sc >= 0.5 ? UITheme.WARN_ORANGE : UITheme.SAFE_GREEN);
                g2.setColor(c);
                g2.fillRoundRect(0, y, fillW, 8, 8, 8);
            }
        };
        barP.setOpaque(false);
        barP.setPreferredSize(new Dimension(260, 40));
        
        JLabel sL = new JLabel(String.format("%.3f", sc));
        sL.setFont(UITheme.FONT_MONO);
        sL.setForeground(UITheme.TEXT_MUTED);
        sL.setHorizontalAlignment(SwingConstants.RIGHT);
        sL.setPreferredSize(new Dimension(60, 40));
        
        JLabel iL = new JLabel();
        iL.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 14));
        if(sc >= 0.85) iL.setText("🚫");
        else if(sc >= 0.5) iL.setText("⚠️");
        else iL.setText("✅");
        iL.setHorizontalAlignment(SwingConstants.CENTER);
        iL.setPreferredSize(new Dimension(40, 40));
        
        JPanel rP = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        rP.setOpaque(false);
        rP.add(barP);
        rP.add(sL);
        rP.add(iL);
        
        row.add(nL, BorderLayout.WEST);
        row.add(rP, BorderLayout.EAST);
        
        breakdownContainer.add(row);
        breakdownContainer.add(Box.createVerticalStrut(8));
    }

    class ScanButton extends JButton {
        private boolean hover = false;
        private boolean pressed = false;
        private boolean loading = false;
        private int rot = 0;
        private Timer loadTimer;

        public ScanButton(String text) {
            super(text);
            setPreferredSize(new Dimension(150, 42));
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setFont(new Font("Segoe UI", Font.BOLD, 13));
            setForeground(Color.WHITE);

            addMouseListener(new MouseAdapter() {
                public void mouseEntered(MouseEvent e) { hover = true; repaint(); }
                public void mouseExited(MouseEvent e) { hover = false; repaint(); }
                public void mousePressed(MouseEvent e) { pressed = true; repaint(); }
                public void mouseReleased(MouseEvent e) { pressed = false; repaint(); }
            });
            
            loadTimer = new Timer(80, e -> {
                rot = (rot + 30) % 360;
                repaint();
            });
        }

        public void setLoading(boolean b) {
            this.loading = b;
            if (b) loadTimer.start(); else loadTimer.stop();
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            Color c1 = UITheme.ACCENT_CYAN;
            Color c2 = new Color(0, 153, 204);
            if (pressed) { c1 = new Color(0, 102, 136); c2 = c1; }
            else if (hover && !loading) { c1 = new Color(0, 255, 255); c2 = UITheme.ACCENT_CYAN; }
            
            GradientPaint gp = new GradientPaint(0, 0, c1, getWidth(), 0, c2);
            g2.setPaint(gp);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
            
            if (loading) {
                g2.setColor(Color.WHITE);
                g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                int cx = getWidth() / 2 - 40;
                int cy = getHeight() / 2 - 8;
                g2.drawArc(cx, cy, 16, 16, -rot, 270);
                
                String dots = rot % 90 < 30 ? "Analyzing." : (rot % 90 < 60 ? "Analyzing.." : "Analyzing...");
                g2.setFont(getFont());
                g2.drawString(dots, cx + 24, cy + 12);
            } else {
                super.paintComponent(g);
            }
        }
    }

    private class StepIndicator extends JPanel {
        private String stepName;
        private String emoji;
        private int state;        // 0=waiting, 1=active, 2=done
        private double score;
        private Color pulseColor; // ← direct field, NOT client property
        private int spinAngle = 0;
        private Timer spinTimer;
        private long pulseStart;

        StepIndicator(String emoji, String stepName) {
            this.emoji = emoji;
            this.stepName = stepName;
            this.state = 0;
            this.pulseColor = UITheme.ACCENT_CYAN;
            this.pulseStart = System.currentTimeMillis();
            setOpaque(false);
            setPreferredSize(new Dimension(110, 70));
        }

        public void setWaiting() {
            state = 0;
            if (spinTimer != null) spinTimer.stop();
            repaint();
        }

        public void setActive() {
            state = 1;
            pulseStart = System.currentTimeMillis();
            spinTimer = new Timer(80, e -> {
                spinAngle = (spinAngle + 30) % 360;
                // update pulse color directly as a field
                pulseColor = UITheme.pulseColor(
                    UITheme.ACCENT_CYAN, pulseStart, 1500);
                repaint();
            });
            spinTimer.start();
        }

        public void setDone(double score) {
            state = 2;
            this.score = score;
            if (spinTimer != null) spinTimer.stop();
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                RenderingHints.VALUE_ANTIALIAS_ON);

            int cx = getWidth() / 2;

            if (state == 0) {
                // Waiting — gray circle
                g2.setColor(new Color(50, 50, 80));
                g2.fillOval(cx - 14, 4, 28, 28);
                g2.setColor(UITheme.TEXT_MUTED);
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 14));
                g2.drawString(emoji, cx - 8, 24);

            } else if (state == 1) {
                // Active — spinning arc + pulsing circle
                g2.setColor(new Color(0, 212, 255, 40));
                g2.fillOval(cx - 16, 2, 32, 32);
                g2.setColor(pulseColor);   // ← use direct field
                g2.setStroke(new BasicStroke(2.5f));
                g2.drawArc(cx - 14, 4, 28, 28, spinAngle, 270);
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 11));
                g2.setColor(UITheme.ACCENT_CYAN);
                g2.drawString(emoji, cx - 7, 23);

            } else {
                // Done — green check
                Color scoreColor = score < 0.5 ? UITheme.SAFE_GREEN
                                 : score < 0.85 ? UITheme.WARN_ORANGE
                                 : UITheme.DANGER_RED;
                g2.setColor(new Color(scoreColor.getRed(),
                                      scoreColor.getGreen(),
                                      scoreColor.getBlue(), 50));
                g2.fillOval(cx - 14, 4, 28, 28);
                g2.setColor(scoreColor);
                g2.setFont(new Font("Segoe UI", Font.BOLD, 15));
                g2.drawString("✓", cx - 7, 25);

                // Score badge
                String sc = String.format("%.2f", score);
                g2.setFont(UITheme.FONT_SMALL);
                g2.setColor(scoreColor);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(sc, cx - fm.stringWidth(sc) / 2, 46);
            }

            // Step name label
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            g2.setColor(state == 1 ? UITheme.ACCENT_CYAN : UITheme.TEXT_MUTED);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(stepName, cx - fm.stringWidth(stepName) / 2, 62);

            g2.dispose();
        }
    }

    class BannerPanel extends JPanel {
        private String txt = "";
        private Color borderC = Color.BLACK, bg1 = Color.BLACK, bg2 = Color.BLACK;
        private float scale = 0.95f;
        
        public BannerPanel() { setOpaque(false); setPreferredSize(new Dimension(800, 80)); }
        
        public void setInfo(String txt, Color b, Color b1, Color b2) {
            this.txt = txt; this.borderC = b; this.bg1 = b1; this.bg2 = b2;
            scale = 0.95f;
            Timer t = new Timer(20, null);
            t.addActionListener(e -> {
                scale += 0.005f;
                if (scale >= 1.0f) { scale = 1.0f; t.stop(); }
                repaint();
            });
            t.start();
        }
        
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            int w = (int)(getWidth() * scale);
            int h = (int)(getHeight() * scale);
            int x = (getWidth() - w)/2;
            int y = (getHeight() - h)/2;
            
            if (bg1 != null) {
                GradientPaint gp = new GradientPaint(x, y, bg1, x, y + h, bg2);
                g2.setPaint(gp);
                g2.fillRoundRect(x, y, w, h, 14, 14);
                
                g2.setColor(borderC);
                g2.setStroke(new BasicStroke(2f));
                g2.drawRoundRect(x, y, w, h, 14, 14);
                
                g2.setColor(Color.WHITE);
                g2.setFont(new Font("Segoe UI", Font.BOLD, (int)(18 * scale)));
                FontMetrics fm = g2.getFontMetrics();
                int tx = x + (w - fm.stringWidth(txt)) / 2;
                int ty = y + (h - fm.getHeight()) / 2 + fm.getAscent();
                g2.drawString(txt, tx, ty);
            }
        }
    }

    class ScoreGauge extends JPanel {
        private double sc = 0;
        private int drawSc = 0;
        public ScoreGauge() { setOpaque(false); setPreferredSize(new Dimension(140, 140)); }
        public void setScore(double sc) {
            this.sc = sc;
            Animator.countUp(0, (int)(sc*100), 1000, v -> { drawSc = v; repaint(); });
        }
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            int cx = getWidth()/2;
            int cy = getHeight()/2;
            
            g2.setStroke(new BasicStroke(12f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(new Color(40, 40, 50));
            g2.drawArc(cx - 50, cy - 50, 100, 100, -225, 270);
            
            Color c = drawSc >= 85 ? UITheme.DANGER_RED : (drawSc >= 50 ? UITheme.WARN_ORANGE : UITheme.SAFE_GREEN);
            g2.setColor(c);
            int sweep = (int)(270 * (drawSc / 100.0));
            g2.drawArc(cx - 50, cy - 50, 100, 100, -225, Math.max(sweep, 1));
            
            g2.setColor(Color.WHITE);
            g2.setFont(UITheme.FONT_NUMBER);
            FontMetrics fm = g2.getFontMetrics();
            String txt = drawSc + "%";
            g2.drawString(txt, cx - fm.stringWidth(txt)/2, cy + 10);
            
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            g2.setColor(UITheme.TEXT_MUTED);
            fm = g2.getFontMetrics();
            String l = "Risk Score";
            g2.drawString(l, cx - fm.stringWidth(l)/2, cy + 30);
        }
    }
}
