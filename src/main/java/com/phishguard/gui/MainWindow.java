package com.phishguard.gui;

import com.phishguard.database.IncidentDAO;
import com.phishguard.email.EmailMonitor;
import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.Constants;

import javax.swing.*;
import java.awt.*;

public class MainWindow extends JFrame {

    private static MainWindow instance;

    private DashboardPanel dashboardPanel;
    private ScannerPanel scannerPanel;
    private LogViewerPanel logViewerPanel;
    private SettingsPanel settingsPanel;

    private JPanel centerContent;
    private CardLayout cardLayout;

    private JLabel statusLabel;
    private JButton startBtn;
    private JButton stopBtn;

    private Thread emailThread;
    private volatile boolean monitorRunning = false;
    private Timer refreshTimer;

    public MainWindow() {
        instance = this;
        initComponents();
        startBackgroundRefresh();
    }

    private void initComponents() {
        setTitle("PhishGuard — Cyber SOC Dashboard v" + Constants.APP_VERSION);
        setSize(1280, 800);
        setMinimumSize(new Dimension(1024, 720));
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setBackground(UITheme.BG_PRIMARY);
        setLocationRelativeTo(null);

        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                stopMonitor();
                com.phishguard.database.DBConnection.getInstance().close();
                dispose();
                System.exit(0);
            }
        });

        setLayout(new BorderLayout());
        getContentPane().setBackground(UITheme.BG_PRIMARY);

        dashboardPanel = new DashboardPanel();
        scannerPanel = new ScannerPanel();
        logViewerPanel = new LogViewerPanel();
        settingsPanel = new SettingsPanel();

        cardLayout = new CardLayout();
        centerContent = new JPanel(cardLayout);
        centerContent.setOpaque(false);
        
        centerContent.add(dashboardPanel, "dashboard");
        centerContent.add(scannerPanel, "scanner");
        centerContent.add(logViewerPanel, "logs");
        centerContent.add(settingsPanel, "settings");

        add(buildSidebar(), BorderLayout.WEST);
        add(centerContent, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
    }

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                    RenderingHints.VALUE_ANTIALIAS_ON);
                
                // Dark gradient background
                GradientPaint grad = new GradientPaint(
                    0, 0, new Color(10, 10, 25),
                    getWidth(), getHeight(), new Color(18, 18, 40));
                g2.setPaint(grad);
                g2.fillRect(0, 0, getWidth(), getHeight());
                
                // Right border line (separator)
                g2.setColor(new Color(0, 212, 255, 60));
                g2.setStroke(new BasicStroke(1f));
                g2.drawLine(getWidth()-1, 0, getWidth()-1, getHeight());
                
                // Subtle dot grid pattern
                g2.setColor(new Color(255, 255, 255, 8));
                for (int x = 10; x < getWidth(); x += 20) {
                    for (int y = 10; y < getHeight(); y += 20) {
                        g2.fillOval(x, y, 2, 2);
                    }
                }
                g2.dispose();
            }
        };
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setPreferredSize(new Dimension(220, 0));
        sidebar.setOpaque(false);

        // Top: Logo
        JPanel top = createLogoPanel();
        sidebar.add(top);
        sidebar.add(Box.createVerticalStrut(20));

        // Center: Navigation
        JPanel[] navItems = new JPanel[4];
        navItems[0] = createNavItem("", "Dashboard", true);
        navItems[1] = createNavItem("", "Scanner", false);
        navItems[2] = createNavItem("", "Incidents", false);
        navItems[3] = createNavItem("", "Settings", false);
        
        String[] cards = {"dashboard", "scanner", "logs", "settings"};
        
        for (int i=0; i<navItems.length; i++) {
            final int idx = i;
            navItems[i].addMouseListener(new java.awt.event.MouseAdapter() {
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    for (int j=0; j<navItems.length; j++) {
                        navItems[j].putClientProperty("selected", j == idx);
                        navItems[j].repaint();
                    }
                    if (cards[idx].equals("logs")) logViewerPanel.loadData();
                    cardLayout.show(centerContent, cards[idx]);
                }
            });
            sidebar.add(navItems[i]);
            sidebar.add(Box.createVerticalStrut(5));
        }

        sidebar.add(Box.createVerticalGlue());

        // Bottom: Monitor Controls
        JPanel bot = new JPanel();
        bot.setOpaque(false);
        bot.setLayout(new BoxLayout(bot, BoxLayout.Y_AXIS));
        bot.setBorder(BorderFactory.createEmptyBorder(20, 10, 30, 10));

        startBtn = new MonitorButton("Start Monitor", UITheme.SAFE_GREEN);
        stopBtn  = new MonitorButton("Stop Monitor", UITheme.DANGER_RED);
        stopBtn.setEnabled(false);

        startBtn.addActionListener(e -> startMonitor());
        stopBtn.addActionListener(e -> stopMonitor());

        bot.add(startBtn);
        bot.add(Box.createVerticalStrut(10));
        bot.add(stopBtn);

        sidebar.add(bot);

        return sidebar;
    }

    private JPanel createLogoPanel() {
        JPanel panel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                    RenderingHints.VALUE_ANTIALIAS_ON);
                
                // Shield shape
                int[] sx = {20, 40, 40, 30, 20};
                int[] sy = {15, 15, 35, 48, 35};
                g2.setColor(new Color(0, 212, 255, 40));
                g2.fillPolygon(sx, sy, 5);
                g2.setColor(new Color(0, 212, 255));
                g2.setStroke(new BasicStroke(1.5f));
                g2.drawPolygon(sx, sy, 5);
                
                // PhishGuard text with glow
                g2.setFont(new Font("Segoe UI", Font.BOLD, 18));
                // Glow layers
                for (int i = 3; i >= 1; i--) {
                    g2.setColor(new Color(0, 212, 255, 20));
                    g2.drawString("PhishGuard", 52 + i, 30 + i);
                    g2.drawString("PhishGuard", 52 - i, 30 - i);
                }
                g2.setColor(new Color(0, 212, 255));
                g2.drawString("PhishGuard", 52, 30);
                
                // Subtitle
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 11));
                g2.setColor(new Color(107, 125, 179));
                g2.drawString("Cyber SOC Dashboard", 52, 46);
                
                g2.dispose();
            }
        };
        panel.setOpaque(false);
        panel.setPreferredSize(new Dimension(220, 80));
        panel.setMaximumSize(new Dimension(220, 80));
        panel.setAlignmentX(Component.CENTER_ALIGNMENT);
        return panel;
    }

    private JPanel createNavItem(String emoji, String label, boolean initialSelected) {
        JPanel item = new JPanel() {
            private boolean hovered = false;
            
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                    RenderingHints.VALUE_ANTIALIAS_ON);
                
                boolean selected = Boolean.TRUE.equals(getClientProperty("selected"));
                
                if (selected) {
                    // Selected: cyan left glow bar + background
                    GradientPaint bg = new GradientPaint(
                        0, 0, new Color(0, 212, 255, 30),
                        getWidth(), 0, new Color(0, 212, 255, 0));
                    g2.setPaint(bg);
                    g2.fillRoundRect(4, 4, getWidth()-8, getHeight()-8, 10, 10);
                    
                    // Left accent bar
                    g2.setColor(new Color(0, 212, 255));
                    g2.fillRoundRect(0, 8, 4, getHeight()-16, 4, 4);
                    
                    // Text glow
                    g2.setFont(new Font("Segoe UI", Font.BOLD, 14));
                    g2.setColor(new Color(0, 212, 255, 60));
                    g2.drawString(emoji + "  " + label, 22, getHeight()/2 + 6);
                    g2.setColor(Color.WHITE);
                    g2.drawString(emoji + "  " + label, 22, getHeight()/2 + 5);
                    
                } else if (hovered) {
                    // Hovered
                    g2.setColor(new Color(255, 255, 255, 10));
                    g2.fillRoundRect(4, 4, getWidth()-8, getHeight()-8, 10, 10);
                    g2.setFont(new Font("Segoe UI", Font.PLAIN, 14));
                    g2.setColor(new Color(180, 190, 220));
                    g2.drawString(emoji + "  " + label, 22, getHeight()/2 + 5);
                } else {
                    // Normal
                    g2.setFont(new Font("Segoe UI", Font.PLAIN, 14));
                    g2.setColor(new Color(107, 125, 179));
                    g2.drawString(emoji + "  " + label, 22, getHeight()/2 + 5);
                }
                g2.dispose();
            }
            
            { // instance initializer
                setOpaque(false);
                putClientProperty("selected", initialSelected);
                setPreferredSize(new Dimension(200, 48));
                setMaximumSize(new Dimension(200, 48));
                setAlignmentX(Component.CENTER_ALIGNMENT);
                addMouseListener(new java.awt.event.MouseAdapter() {
                    public void mouseEntered(java.awt.event.MouseEvent e) { 
                        hovered = true; repaint(); 
                        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    }
                    public void mouseExited(java.awt.event.MouseEvent e) { 
                        hovered = false; repaint(); 
                        setCursor(Cursor.getDefaultCursor());
                    }
                });
            }
        };
        return item;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(UITheme.BG_PRIMARY);
        bar.setPreferredSize(new Dimension(0, 30));
        bar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UITheme.BORDER_COLOR));

        statusLabel = new JLabel("  Monitoring Stopped  |  Scanned: 0  |  Threats: 0  |  Blocked: 0  |  v" + Constants.APP_VERSION);
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        statusLabel.setForeground(UITheme.TEXT_MUTED);
        bar.add(statusLabel, BorderLayout.WEST);

        return bar;
    }

    private void startBackgroundRefresh() {
        refreshTimer = new Timer(10000, e -> {
            dashboardPanel.refresh();
            updateStatusBar();
        });
        refreshTimer.setInitialDelay(2000);
        refreshTimer.start();
    }

    private void updateStatusBar() {
        long emailsProcessed = EmailMonitor.getEmailsProcessed();
        long threatsFound    = EmailMonitor.getThreatsFound();
        int  dbIncidents     = IncidentDAO.getIncidentsByDecision(Constants.DECISION_HIGH_RISK);

        statusLabel.setText(
            (monitorRunning ? "  Monitoring Active" : "  Monitoring Stopped")
            + "  |  Scanned: " + emailsProcessed
            + "  |  Threats: "    + threatsFound
            + "  |  Blocked: "     + dbIncidents
            + "  |  v" + Constants.APP_VERSION
        );
    }

    private void startMonitor() {
        if (monitorRunning) return;
        emailThread = new Thread(new EmailMonitor(), "EmailMonitor");
        emailThread.setDaemon(true);
        emailThread.start();
        monitorRunning = true;
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        updateStatusBar();
    }

    private void stopMonitor() {
        if (!monitorRunning) return;
        EmailMonitor.stop();
        monitorRunning = false;
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        updateStatusBar();
    }

    public static void showAlert(RiskScorer scorer) {
        if (instance == null) return;
        SwingUtilities.invokeLater(() -> AlertDialog.show(scorer));
    }

    // -- Custom Components --

    // (NavButton removed as replaced by createNavItem)

    class MonitorButton extends JButton {
        private Color baseColor;
        private boolean hover = false;
        public MonitorButton(String text, Color baseColor) {
            super(text);
            this.baseColor = baseColor;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setForeground(Color.WHITE);
            setFont(new Font("Segoe UI", Font.BOLD, 13));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setPreferredSize(new Dimension(200, 40));
            setMaximumSize(new Dimension(200, 40));
            
            addMouseListener(new java.awt.event.MouseAdapter() {
                public void mouseEntered(java.awt.event.MouseEvent e) { hover = true; repaint(); }
                public void mouseExited(java.awt.event.MouseEvent e) { hover = false; repaint(); }
            });
        }
        
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            if (!isEnabled()) {
                g2.setColor(UITheme.BG_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                setForeground(UITheme.TEXT_MUTED);
            } else {
                Color c = hover ? baseColor.brighter() : baseColor;
                int darkR = Math.max(0, c.getRed() - 70);
                int darkG = Math.max(0, c.getGreen() - 70);
                int darkB = Math.max(0, c.getBlue() - 70);
                GradientPaint gp = new GradientPaint(0, 0, c, 0, getHeight(), new Color(darkR, darkG, darkB));
                g2.setPaint(gp);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                setForeground(Color.WHITE);
            }
            
            super.paintComponent(g);
        }
    }
}
