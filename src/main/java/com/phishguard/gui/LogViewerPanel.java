package com.phishguard.gui;

import com.phishguard.database.IncidentDAO;
import com.phishguard.engine.RiskScorer;
import com.phishguard.report.PDFReportGenerator;
import com.phishguard.utils.Constants;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class LogViewerPanel extends JPanel {

    private DefaultTableModel tableModel;
    private JTable incidentTable;
    private JComboBox<String> filterCombo;
    private JLabel countLabel;
    private List<RiskScorer> allIncidents = new ArrayList<>();

    private static final String[] COLS = {"#", "Timestamp", "Sender", "URL", "Score", "Decision"};

    public LogViewerPanel() {
        setLayout(new BorderLayout(0, 16));
        setBackground(UITheme.BG_PRIMARY);
        setBorder(BorderFactory.createEmptyBorder(16, 24, 16, 24));

        add(buildHeaderBar(), BorderLayout.NORTH);
        add(buildTableArea(), BorderLayout.CENTER);

        loadData();
    }

    private JPanel buildHeaderBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);

        JLabel title = new JLabel("Incident Log");
        title.setFont(new Font("Segoe UI", Font.BOLD, 18));
        title.setForeground(UITheme.ACCENT_CYAN);
        bar.add(title, BorderLayout.WEST);

        JPanel rightGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        rightGroup.setOpaque(false);

        countLabel = new JLabel("Loading...");
        countLabel.setFont(UITheme.FONT_BODY);
        countLabel.setForeground(UITheme.TEXT_MUTED);
        rightGroup.add(countLabel);

        filterCombo = new JComboBox<>(new String[]{
            "All", "High Risk", "Suspicious", "Safe", "Last 24h", "Last 7 Days"
        });
        filterCombo.setBackground(UITheme.BG_PRIMARY);
        filterCombo.setForeground(UITheme.TEXT_PRIMARY);
        filterCombo.setFont(new Font("Segoe UI", Font.BOLD, 12));
        filterCombo.setPreferredSize(new Dimension(130, 32));
        filterCombo.addActionListener(e -> applyFilter());
        rightGroup.add(filterCombo);

        JButton refreshBtn = createOutlineBtn("Refresh");
        refreshBtn.addActionListener(e -> loadData());
        rightGroup.add(refreshBtn);

        JButton exportBtn = new JButton("Export PDF Report") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                GradientPaint gp = new GradientPaint(0, 0, UITheme.ACCENT_CYAN, getWidth(), 0, new Color(0, 102, 170));
                g2.setPaint(gp);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                super.paintComponent(g);
            }
        };
        exportBtn.setContentAreaFilled(false);
        exportBtn.setBorderPainted(false);
        exportBtn.setFocusPainted(false);
        exportBtn.setForeground(Color.WHITE);
        exportBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        exportBtn.setPreferredSize(new Dimension(160, 32));
        exportBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        exportBtn.addActionListener(e -> exportPDF());
        rightGroup.add(exportBtn);

        bar.add(rightGroup, BorderLayout.EAST);
        return bar;
    }

    private JButton createOutlineBtn(String text) {
        JButton btn = new JButton(text);
        btn.setContentAreaFilled(false);
        btn.setForeground(UITheme.ACCENT_CYAN);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setBorder(BorderFactory.createLineBorder(UITheme.ACCENT_CYAN, 1));
        btn.setPreferredSize(new Dimension(100, 32));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private JPanel buildTableArea() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);

        tableModel = new DefaultTableModel(COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        incidentTable = new JTable(tableModel);
        incidentTable.setBackground(UITheme.BG_SECONDARY);
        incidentTable.setForeground(UITheme.TEXT_PRIMARY);
        incidentTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        incidentTable.getTableHeader().setBackground(UITheme.BG_CARD);
        incidentTable.getTableHeader().setForeground(UITheme.ACCENT_CYAN);
        incidentTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        incidentTable.setRowHeight(36);
        incidentTable.setGridColor(UITheme.BORDER_COLOR);
        incidentTable.setShowVerticalLines(false);
        incidentTable.setIntercellSpacing(new Dimension(0, 0));

        incidentTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        incidentTable.getColumnModel().getColumn(1).setPreferredWidth(140);
        incidentTable.getColumnModel().getColumn(3).setPreferredWidth(400);

        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, foc, row, col);

                String decision = (String) t.getModel().getValueAt(row, 5);
                setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

                Color baseBg;
                if (Constants.DECISION_HIGH_RISK.equals(decision)) {
                    baseBg = new Color(45, 10, 18);
                    if (col == 0) setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 3, 0, 0, UITheme.DANGER_RED),
                            BorderFactory.createEmptyBorder(0, 7, 0, 10)));
                } else if (Constants.DECISION_SUSPICIOUS.equals(decision)) {
                    baseBg = new Color(45, 26, 0);
                    if (col == 0) setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 3, 0, 0, UITheme.WARN_ORANGE),
                            BorderFactory.createEmptyBorder(0, 7, 0, 10)));
                } else {
                    baseBg = new Color(0, 26, 13);
                    if (col == 0) setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 3, 0, 0, UITheme.SAFE_GREEN),
                            BorderFactory.createEmptyBorder(0, 7, 0, 10)));
                }

                // Hover logic: incidentTable.getClientProperty("hoveredRow")
                Object hRotObj = incidentTable.getClientProperty("hoveredRow");
                boolean hovered = (hRotObj != null && (int)hRotObj == row);

                if (sel) setBackground(baseBg.brighter().brighter());
                else if (hovered) setBackground(baseBg.brighter());
                else setBackground(baseBg);

                if (col == 3) { // URL
                    setFont(UITheme.FONT_MONO);
                    setForeground(UITheme.TEXT_MUTED);
                } else {
                    setFont(new Font("Segoe UI", Font.PLAIN, 12));
                    setForeground(UITheme.TEXT_PRIMARY);
                }
                
                if (col == 5 && v != null) {
                    if (v.toString().contains("HIGH")) setForeground(UITheme.DANGER_RED);
                    else if (v.toString().contains("SUSP")) setForeground(UITheme.WARN_ORANGE);
                    else setForeground(UITheme.SAFE_GREEN);
                }

                return this;
            }
        };

        for (int i = 0; i < incidentTable.getColumnCount(); i++) {
            incidentTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        incidentTable.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                int row = incidentTable.rowAtPoint(e.getPoint());
                if (row != -1) {
                    incidentTable.putClientProperty("hoveredRow", row);
                    incidentTable.repaint();
                }
            }
        });
        incidentTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseExited(MouseEvent e) {
                incidentTable.putClientProperty("hoveredRow", -1);
                incidentTable.repaint();
            }
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = incidentTable.getSelectedRow();
                    if (row >= 0 && row < allIncidents.size()) {
                        RiskScorer scorer = allIncidents.get(row);
                        new IncidentDetailDialog(scorer).setVisible(true);
                    }
                }
            }
        });

        JScrollPane sp = new JScrollPane(incidentTable);
        sp.setBackground(UITheme.BG_SECONDARY);
        sp.getViewport().setBackground(UITheme.BG_SECONDARY);
        sp.setBorder(BorderFactory.createLineBorder(UITheme.BORDER_COLOR));
        wrapper.add(sp, BorderLayout.CENTER);

        return wrapper;
    }

    void loadData() {
        new SwingWorker<List<RiskScorer>, Void>() {
            @Override protected List<RiskScorer> doInBackground() {
                return IncidentDAO.getRecentIncidents(100);
            }
            @Override protected void done() {
                try {
                    allIncidents = get();
                    applyFilter();
                } catch (Exception e) {
                    System.err.println("[LogViewer] Load failed: " + e.getMessage());
                }
            }
        }.execute();
    }

    private void applyFilter() {
        String filter = (String) filterCombo.getSelectedItem();
        List<RiskScorer> filtered;

        if (filter == null || filter.equals("All")) {
            filtered = allIncidents;
        } else if (filter.equals("High Risk")) {
            filtered = allIncidents.stream().filter(s -> Constants.DECISION_HIGH_RISK.equals(s.decision)).collect(Collectors.toList());
        } else if (filter.equals("Suspicious")) {
            filtered = allIncidents.stream().filter(s -> Constants.DECISION_SUSPICIOUS.equals(s.decision)).collect(Collectors.toList());
        } else if (filter.equals("Safe")) {
            filtered = allIncidents.stream().filter(s -> Constants.DECISION_SAFE.equals(s.decision)).collect(Collectors.toList());
        } else {
             // Fallback for time filters if timestamp logic is tricky, just show all for now
            filtered = allIncidents;
        }

        tableModel.setRowCount(0);
        int rowNum = 1;
        for (RiskScorer s : filtered) {
            tableModel.addRow(new Object[]{
                rowNum++,
                s.timestamp != null ? s.timestamp.toString() : "—",
                s.senderEmail != null ? s.senderEmail : "—",
                s.url != null && s.url.length() > 60 ? s.url.substring(0, 57) + "..." : s.url,
                String.format("%.3f", s.finalScore),
                s.decision
            });
        }
        countLabel.setText(filtered.size() + " incident" + (filtered.size() != 1 ? "s" : ""));
    }

    private void exportPDF() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save PDF Report");
        chooser.setFileFilter(new FileNameExtensionFilter("PDF Files (*.pdf)", "pdf"));
        chooser.setSelectedFile(new File("PhishGuard_Report.pdf"));

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        if (!target.getName().endsWith(".pdf")) {
            target = new File(target.getAbsolutePath() + ".pdf");
        }
        final File finalTarget = target;

        new SwingWorker<File, Void>() {
            @Override protected File doInBackground() throws Exception {
                return PDFReportGenerator.generateReport(allIncidents);
            }
            @Override protected void done() {
                try {
                    File temp = get();
                    Files.copy(temp.toPath(), finalTarget.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    JOptionPane.showMessageDialog(LogViewerPanel.this,
                        "PDF report saved to:\n" + finalTarget.getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(LogViewerPanel.this,
                        "Export failed: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    class IncidentDetailDialog extends JDialog {
        public IncidentDetailDialog(RiskScorer scorer) {
            setUndecorated(true);
            setModal(true);
            setSize(500, 440);
            setLocationRelativeTo(LogViewerPanel.this);

            JPanel root = new JPanel(new BorderLayout()) {
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    Graphics2D g2 = (Graphics2D) g;
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(new Color(20, 20, 40)); 
                    g2.fillRect(0, 0, getWidth(), getHeight());
                    g2.setColor(UITheme.BORDER_COLOR);
                    g2.drawRect(0, 0, getWidth() - 1, getHeight() - 1);
                }
            };
            root.setBorder(BorderFactory.createEmptyBorder(20, 24, 20, 24));

            JLabel title = new JLabel("Incident Details");
            title.setFont(new Font("Segoe UI", Font.BOLD, 18));
            title.setForeground(Color.WHITE);
            root.add(title, BorderLayout.NORTH);

            JPanel center = new JPanel();
            center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
            center.setOpaque(false);
            center.add(Box.createVerticalStrut(16));

            addAttr(center, "URL:", scorer.url);
            addAttr(center, "Timestamp:", scorer.timestamp != null ? scorer.timestamp.toString() : "N/A");
            addAttr(center, "Sender:", scorer.senderEmail != null ? scorer.senderEmail : "Unknown");
            addAttr(center, "Action Taken:", scorer.actionTaken != null ? scorer.actionTaken : "None");
            center.add(Box.createVerticalStrut(16));

            JLabel scoreTitle = new JLabel("Layer Breakdown:");
            scoreTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
            scoreTitle.setForeground(UITheme.ACCENT_CYAN);
            center.add(scoreTitle);
            center.add(Box.createVerticalStrut(8));

            addMiniBar(center, "Sender", scorer.senderScore);
            addMiniBar(center, "NLP", scorer.textScore);
            addMiniBar(center, "AI Mod", scorer.aiModelScore);
            addMiniBar(center, "Threat", scorer.threatIntelScore);
            addMiniBar(center, "Visual", scorer.visualScore);

            root.add(center, BorderLayout.CENTER);

            JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
            bottom.setOpaque(false);
            JButton closeBtn = new JButton("Close");
            closeBtn.setContentAreaFilled(false);
            closeBtn.setForeground(UITheme.DANGER_RED);
            closeBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
            closeBtn.setBorder(BorderFactory.createLineBorder(UITheme.DANGER_RED, 1));
            closeBtn.setPreferredSize(new Dimension(80, 28));
            closeBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
            closeBtn.addActionListener(e -> dispose());
            bottom.add(closeBtn);

            root.add(bottom, BorderLayout.SOUTH);

            setContentPane(root);
        }

        private void addAttr(JPanel container, String lbl, String val) {
            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.setMaximumSize(new Dimension(450, 24));
            JLabel l = new JLabel(lbl);
            l.setFont(new Font("Segoe UI", Font.BOLD, 12));
            l.setForeground(UITheme.TEXT_MUTED);
            l.setPreferredSize(new Dimension(100, 24));
            
            JTextArea v = new JTextArea(val);
            v.setFont(UITheme.FONT_MONO);
            v.setForeground(UITheme.TEXT_PRIMARY);
            v.setBackground(new Color(20, 20, 40));
            v.setLineWrap(true);
            v.setWrapStyleWord(true);
            v.setEditable(false);
            
            row.add(l, BorderLayout.WEST);
            row.add(v, BorderLayout.CENTER);
            container.add(row);
            container.add(Box.createVerticalStrut(4));
        }

        private void addMiniBar(JPanel container, String layer, double score) {
            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.setMaximumSize(new Dimension(450, 24));

            JLabel l = new JLabel(layer);
            l.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            l.setForeground(UITheme.TEXT_PRIMARY);
            l.setPreferredSize(new Dimension(100, 24));

            JPanel bar = new JPanel() {
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    Graphics2D g2 = (Graphics2D) g;
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(UITheme.BG_PRIMARY);
                    g2.fillRoundRect(0, 6, 200, 10, 10, 10);

                    Color c = score >= 0.85 ? UITheme.DANGER_RED : (score >= 0.5 ? UITheme.WARN_ORANGE : UITheme.SAFE_GREEN);
                    g2.setColor(c);
                    g2.fillRoundRect(0, 6, (int)(200 * score), 10, 10, 10);
                }
            };
            bar.setOpaque(false);
            bar.setPreferredSize(new Dimension(210, 24));

            JLabel s = new JLabel(String.format("%.3f", score));
            s.setFont(UITheme.FONT_MONO);
            s.setForeground(UITheme.TEXT_MUTED);

            JPanel right = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
            right.setOpaque(false);
            right.add(bar);
            right.add(s);

            row.add(l, BorderLayout.WEST);
            row.add(right, BorderLayout.CENTER);
            container.add(row);
        }
    }
}
