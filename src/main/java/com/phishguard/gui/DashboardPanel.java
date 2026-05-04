package com.phishguard.gui;

import com.phishguard.database.IncidentDAO;
import com.phishguard.engine.RiskScorer;
import com.phishguard.report.ChartBuilder;
import com.phishguard.utils.Constants;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.StandardBarPainter;
import org.jfree.chart.title.LegendTitle;
import org.jfree.chart.title.TextTitle;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.geom.Point2D;
import java.util.List;

public class DashboardPanel extends JPanel {

    private StatCard cardTotal, cardThreats, cardBlocked, cardAvg;
    private JPanel chartArea;
    private DefaultTableModel recentModel;
    private JTable recentTable;

    public DashboardPanel() {
        setLayout(new BorderLayout(0, 16));
        setBackground(UITheme.BG_PRIMARY);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        add(buildStatsBar(), BorderLayout.NORTH);
        add(buildChartArea(), BorderLayout.CENTER);
        add(buildRecentTable(), BorderLayout.SOUTH);

        refresh();
    }

    // -- SEC 1: STAT CARDS
    private JPanel buildStatsBar() {
        JPanel bar = new JPanel(new GridLayout(1, 4, 16, 0));
        bar.setOpaque(false);
        bar.setPreferredSize(new Dimension(0, 130));

        cardTotal   = new StatCard("Emails Scanned", UITheme.ACCENT_CYAN, "", false);
        cardThreats = new StatCard("Threats Found",  UITheme.WARN_ORANGE, "", false);
        cardBlocked = new StatCard("URLs Blocked",   UITheme.DANGER_RED,  "", false);
        cardAvg     = new StatCard("Avg Risk Score", UITheme.SAFE_GREEN,  "", true);

        bar.add(cardTotal);
        bar.add(cardThreats);
        bar.add(cardBlocked);
        bar.add(cardAvg);
        return bar;
    }

    class StatCard extends JPanel {
        private int value = 0;
        private int targetValue = 0;
        private String label;
        private Color accent;
        private String icon;
        private boolean isScore;

        public StatCard(String label, Color accent, String icon, boolean isScore) {
            this.label = label;
            this.accent = accent;
            this.icon = icon;
            this.isScore = isScore;
            setOpaque(false);
        }

        public void updateValue(int to) {
            if (this.targetValue == to) return;
            int from = this.value;
            this.targetValue = to;
            Animator.countUp(from, to, 800, v -> {
                this.value = v;
                repaint();
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                                RenderingHints.VALUE_ANTIALIAS_ON);
            
            int w = getWidth(), h = getHeight();
            String displayValue = isScore ? value + "%" : String.valueOf(value);
            
            // Main card gradient background
            GradientPaint cardBg = new GradientPaint(
                0, 0, new Color(26, 26, 53),
                0, h, new Color(20, 20, 42));
            g2.setPaint(cardBg);
            g2.fillRoundRect(0, 0, w, h, 16, 16);
            
            // Top accent bar (gradient)
            GradientPaint topBar = new GradientPaint(
                0, 0, accent,
                w, 0, new Color(accent.getRed(), 
                                accent.getGreen(), 
                                accent.getBlue(), 80));
            g2.setPaint(topBar);
            g2.fillRoundRect(0, 0, w, 5, 5, 5);
            
            // Inner glow (subtle radial from top)
            RadialGradientPaint glow = new RadialGradientPaint(
                new Point2D.Float(w/2f, 0),
                w * 0.7f,
                new float[]{0f, 1f},
                new Color[]{new Color(accent.getRed(), 
                                      accent.getGreen(), 
                                      accent.getBlue(), 25),
                            new Color(0, 0, 0, 0)});
            g2.setPaint(glow);
            g2.fillRect(0, 0, w, h);
            
            // Border
            g2.setColor(new Color(accent.getRed(), 
                                  accent.getGreen(), 
                                  accent.getBlue(), 50));
            g2.setStroke(new BasicStroke(1f));
            g2.drawRoundRect(0, 0, w-1, h-1, 16, 16);
            
            // Icon top-right
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 20));
            g2.setColor(new Color(accent.getRed(), 
                                  accent.getGreen(), 
                                  accent.getBlue(), 120));
            g2.drawString(icon, w - 36, 32);
            
            // Large animated value
            g2.setFont(new Font("Segoe UI", Font.BOLD, 36));
            g2.setColor(Color.WHITE);
            FontMetrics fm = g2.getFontMetrics();
            int vx = (w - fm.stringWidth(displayValue)) / 2;
            g2.drawString(displayValue, vx, 68);
            
            // Label
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            g2.setColor(new Color(160, 170, 200));
            FontMetrics fm2 = g2.getFontMetrics();
            int lx = (w - fm2.stringWidth(label)) / 2;
            g2.drawString(label, lx, 90);
            
            g2.dispose();
        }
    }

    // -- SEC 2: CHARTS
    private JPanel buildChartArea() {
        chartArea = new JPanel(new GridLayout(1, 2, 16, 0));
        chartArea.setOpaque(false);
        rebuildCharts();
        return chartArea;
    }

    private void rebuildCharts() {
        chartArea.removeAll();

        JFreeChart pie = ChartBuilder.buildPieChart();
        applyDarkThemePie(pie);
        ChartPanel pPanel = new ChartPanel(pie);
        pPanel.setBackground(UITheme.BG_SECONDARY);
        pPanel.setBorder(BorderFactory.createLineBorder(UITheme.BORDER_COLOR));

        JFreeChart bar = ChartBuilder.buildBarChart();
        applyDarkThemeBar(bar);
        ChartPanel bPanel = new ChartPanel(bar);
        bPanel.setBackground(UITheme.BG_SECONDARY);
        bPanel.setBorder(BorderFactory.createLineBorder(UITheme.BORDER_COLOR));

        chartArea.add(pPanel);
        chartArea.add(bPanel);
        chartArea.revalidate();
        chartArea.repaint();
    }

    @SuppressWarnings("rawtypes")
    private void applyDarkThemePie(JFreeChart chart) {
        if (chart == null) return;
        chart.setBackgroundPaint(UITheme.BG_PRIMARY);
        TextTitle t = chart.getTitle();
        if (t != null) {
            t.setPaint(UITheme.TEXT_PRIMARY);
            t.setFont(new Font("Segoe UI", Font.BOLD, 14));
        }
        LegendTitle lt = chart.getLegend();
        if (lt != null) {
            lt.setBackgroundPaint(UITheme.BG_PRIMARY);
            lt.setItemPaint(UITheme.TEXT_PRIMARY);
            lt.setItemFont(new Font("Segoe UI", Font.PLAIN, 11));
        }

        PiePlot plot = (PiePlot) chart.getPlot();
        plot.setBackgroundPaint(UITheme.BG_SECONDARY);
        plot.setOutlineVisible(false);
        plot.setLabelBackgroundPaint(new Color(20, 20, 40, 200));
        plot.setLabelPaint(Color.WHITE);
        plot.setLabelFont(new Font("Segoe UI", Font.PLAIN, 11));
        plot.setLabelShadowPaint(null);
        plot.setLabelOutlinePaint(null);
        plot.setSectionPaint("Safe", UITheme.SAFE_GREEN);
        plot.setSectionPaint("Suspicious", UITheme.WARN_ORANGE);
        plot.setSectionPaint("High Risk", UITheme.DANGER_RED);
    }

    private void applyDarkThemeBar(JFreeChart chart) {
        if (chart == null) return;
        chart.setBackgroundPaint(UITheme.BG_PRIMARY);
        TextTitle t = chart.getTitle();
        if (t != null) {
            t.setPaint(UITheme.TEXT_PRIMARY);
            t.setFont(new Font("Segoe UI", Font.BOLD, 14));
        }

        CategoryPlot plot = (CategoryPlot) chart.getPlot();
        plot.setBackgroundPaint(UITheme.BG_SECONDARY);
        plot.setOutlineVisible(false);
        plot.setRangeGridlinePaint(UITheme.BORDER_COLOR);
        plot.setDomainGridlinePaint(UITheme.BORDER_COLOR);

        CategoryAxis dAxis = plot.getDomainAxis();
        dAxis.setTickLabelPaint(UITheme.TEXT_MUTED);
        dAxis.setLabelPaint(Color.WHITE);
        dAxis.setAxisLinePaint(UITheme.BORDER_COLOR);

        NumberAxis rAxis = (NumberAxis) plot.getRangeAxis();
        rAxis.setTickLabelPaint(UITheme.TEXT_MUTED);
        rAxis.setLabelPaint(Color.WHITE);
        rAxis.setAxisLinePaint(UITheme.BORDER_COLOR);

        BarRenderer r = (BarRenderer) plot.getRenderer();
        r.setBarPainter(new StandardBarPainter());
        r.setSeriesPaint(0, UITheme.ACCENT_CYAN);
        r.setSeriesPaint(0, new GradientPaint(0, 0, UITheme.ACCENT_CYAN, 0, 0, new Color(0, 102, 170)));
        r.setShadowVisible(false);
    }

    // -- SEC 3: RECENT THREATS TABLE
    private JPanel buildRecentTable() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setOpaque(false);
        panel.setPreferredSize(new Dimension(0, 220));

        JLabel heading = new JLabel("Recent Threats");
        heading.setFont(new Font("Segoe UI", Font.BOLD, 14));
        heading.setForeground(UITheme.ACCENT_CYAN);
        panel.add(heading, BorderLayout.NORTH);

        String[] cols = {"Sender", "URL", "Score", "Decision"};
        recentModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        recentTable = new JTable(recentModel);
        styleTable(recentTable);
        recentTable.getColumnModel().getColumn(1).setPreferredWidth(350);

        JScrollPane sp = new JScrollPane(recentTable);
        sp.setBackground(UITheme.BG_SECONDARY);
        sp.getViewport().setBackground(UITheme.BG_SECONDARY);
        sp.setBorder(BorderFactory.createLineBorder(UITheme.BORDER_COLOR));
        panel.add(sp, BorderLayout.CENTER);
        return panel;
    }

    private void styleTable(JTable table) {
        table.setBackground(UITheme.BG_SECONDARY);
        table.setForeground(UITheme.TEXT_PRIMARY);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        table.getTableHeader().setBackground(UITheme.BG_CARD);
        table.getTableHeader().setForeground(UITheme.ACCENT_CYAN);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        table.setRowHeight(32);
        table.setGridColor(UITheme.BORDER_COLOR);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setShowVerticalLines(false);

        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean focus, int row, int col) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(
                    t, val, sel, focus, row, col);
                
                String decision = (String) t.getValueAt(row, 3); // Decision column
                
                // Row base color
                Color bg, fg, border;
                if (decision != null && decision.contains("HIGH")) {
                    bg = new Color(45, 10, 18);
                    fg = new Color(255, 120, 140);
                    border = new Color(255, 34, 68);
                } else if (decision != null && decision.contains("SUSPICIOUS")) {
                    bg = new Color(45, 28, 0);
                    fg = new Color(255, 180, 80);
                    border = new Color(255, 136, 0);
                } else {
                    bg = new Color(0, 30, 18);
                    fg = new Color(80, 220, 140);
                    border = new Color(0, 255, 136);
                }
                
                if (sel) bg = bg.brighter();
                label.setBackground(bg);
                label.setForeground(col == 1 ? new Color(0, 180, 220) : fg);
                label.setFont(col == 1 ? new Font("Consolas", Font.PLAIN, 11)
                                        : new Font("Segoe UI", Font.PLAIN, 12));
                label.setBorder(col == 0
                    ? BorderFactory.createMatteBorder(0, 3, 0, 0, border)
                    : BorderFactory.createEmptyBorder(0, 8, 0, 8));
                label.setOpaque(true);
                return label;
            }
        };
        
        class BadgeRenderer extends DefaultTableCellRenderer {
            private String dec = "";
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                dec = v != null ? v.toString() : "";
                Component c = renderer.getTableCellRendererComponent(t, v, sel, foc, row, col);
                setText(""); 
                return c;
            }
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setFont(new Font("Segoe UI", Font.BOLD, 11));
                FontMetrics fm = g2.getFontMetrics();
                
                Color bg = UITheme.SAFE_GREEN;
                String txt = "SAFE";
                if (Constants.DECISION_HIGH_RISK.equals(dec)) { bg = UITheme.DANGER_RED; txt = "HIGH RISK"; }
                else if (Constants.DECISION_SUSPICIOUS.equals(dec)) { bg = UITheme.WARN_ORANGE; txt = "SUSPICIOUS"; }
                
                int w = fm.stringWidth(txt) + 16;
                int h = 20;
                int y = (getHeight() - h) / 2;
                
                g2.setColor(bg);
                g2.fillRoundRect(10, y, w, h, h, h);
                
                g2.setColor(new Color(13, 13, 26)); // text color inside pill
                g2.drawString(txt, 18, y + 14);
            }
        }

        for (int i = 0; i < table.getColumnCount(); i++) {
            if (i == 3) table.getColumnModel().getColumn(i).setCellRenderer(new BadgeRenderer());
            else table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }
    }

    public void refresh() {
        new SwingWorker<Object[], Void>() {
            @Override
            protected Object[] doInBackground() {
                int total     = IncidentDAO.getTotalIncidents();
                int suspicious = IncidentDAO.getIncidentsByDecision(Constants.DECISION_SUSPICIOUS);
                int highRisk  = IncidentDAO.getIncidentsByDecision(Constants.DECISION_HIGH_RISK);
                int threats   = suspicious + highRisk;
                int blocked   = IncidentDAO.getIncidentsByDecision(Constants.DECISION_HIGH_RISK);
                double avg    = IncidentDAO.getAverageRiskScore();
                List<RiskScorer> recent = IncidentDAO.getRecentIncidents(5);
                return new Object[]{total, threats, blocked, avg, recent};
            }

            @Override
            @SuppressWarnings("unchecked")
            protected void done() {
                try {
                    Object[] r = get();
                    cardTotal.updateValue((int) r[0]);
                    cardThreats.updateValue((int) r[1]);
                    cardBlocked.updateValue((int) r[2]);
                    cardAvg.updateValue((int) ((double) r[3] * 100));

                    rebuildCharts();

                    List<RiskScorer> recent = (List<RiskScorer>) r[4];
                    recentModel.setRowCount(0);
                    for (RiskScorer s : recent) {
                        recentModel.addRow(new Object[]{
                            s.senderEmail != null ? s.senderEmail : "—",
                            s.url.length() <= 80 ? s.url : s.url.substring(0, 77) + "...",
                            String.format("%.3f", s.finalScore),
                            s.decision
                        });
                    }
                } catch (Exception e) {
                    System.err.println("[DashboardPanel] Refresh error: " + e.getMessage());
                }
            }
        }.execute();
    }
}
