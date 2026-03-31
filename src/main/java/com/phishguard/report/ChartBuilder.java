package com.phishguard.report;

import com.phishguard.database.IncidentDAO;
import com.phishguard.utils.Constants;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.GradientBarPainter;
import org.jfree.chart.title.LegendTitle;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * PhishGuard - ChartBuilder.java
 * -------------------------------------------------
 * Builds JFreeChart objects for the DashboardPanel.
 * All charts use the PhishGuard dark theme:
 *   Background: #1e1e2e, text: white, accent: #4f8ef7
 *
 * JFreeChart 1.5.4 API is used throughout.
 */
public final class ChartBuilder {

    // ── Theme colors ──────────────────────────────────────────────────────
    private static final Color BG_DARK       = new Color(0x1e1e2e);

    private ChartBuilder() {}

    // ── Pie Chart ─────────────────────────────────────────────────────────

    /**
     * Builds a dark-themed pie chart showing detection breakdown:
     * Safe / Suspicious / High Risk counts from the incidents DB table.
     *
     * @return configured JFreeChart pie chart
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static JFreeChart buildPieChart() {
        DefaultPieDataset<String> dataset = new DefaultPieDataset<>();

        int safe      = IncidentDAO.getIncidentsByDecision(Constants.DECISION_SAFE);
        int suspicious = IncidentDAO.getIncidentsByDecision(Constants.DECISION_SUSPICIOUS);
        int highRisk  = IncidentDAO.getIncidentsByDecision(Constants.DECISION_HIGH_RISK);

        // Ensure chart is never empty
        if (safe + suspicious + highRisk == 0) {
            dataset.setValue("No data yet", 1);
        } else {
            if (safe > 0)       dataset.setValue("Safe",        safe);
            if (suspicious > 0) dataset.setValue("Suspicious",  suspicious);
            if (highRisk > 0)   dataset.setValue("High Risk",   highRisk);
        }

        JFreeChart chart = ChartFactory.createPieChart(
            "Detection Breakdown", dataset, true, true, false
        );

        // Apply dark theme
        chart.setBackgroundPaint(new Color(13, 13, 26));
        chart.getTitle().setPaint(Color.WHITE);
        chart.getTitle().setFont(new Font("Segoe UI", Font.BOLD, 14));

        LegendTitle legend = chart.getLegend();
        if (legend != null) {
            legend.setBackgroundPaint(new Color(20, 20, 40));
            legend.setItemPaint(Color.WHITE);
            legend.setItemFont(new Font("Segoe UI", Font.PLAIN, 11));
        }

        PiePlot plot = (PiePlot) chart.getPlot();
        // Set dark background
        plot.setBackgroundPaint(new Color(20, 20, 40));
        plot.setShadowPaint(null);
        plot.setOutlineVisible(false);

        // Neon colors for slices
        plot.setSectionPaint("Safe",      new Color(0, 255, 136));
        plot.setSectionPaint("Suspicious",new Color(255, 136, 0));
        plot.setSectionPaint("High Risk", new Color(255, 34, 68));
        plot.setSectionPaint("No data yet", new Color(0x666680));

        // Label styling
        plot.setLabelFont(new Font("Segoe UI", Font.PLAIN, 11));
        plot.setLabelBackgroundPaint(new Color(20, 20, 40, 180));
        plot.setLabelOutlinePaint(new Color(30, 45, 90));
        plot.setLabelShadowPaint(null);
        plot.setLabelPaint(Color.WHITE);

        // Explode high risk slice for emphasis
        plot.setExplodePercent("High Risk", 0.08);

        return chart;
    }

    // ── Bar Chart ─────────────────────────────────────────────────────────

    /**
     * Builds a dark-themed bar chart showing threat activity over the last 7 days.
     * Queries the incidents table; falls back to sample data if the table is empty.
     *
     * @return configured JFreeChart bar chart
     */
    public static JFreeChart buildBarChart() {
        DefaultCategoryDataset dataset = new DefaultCategoryDataset();

        try {
            com.phishguard.database.DBConnection dbConn =
                com.phishguard.database.DBConnection.getInstance();
            Connection conn = dbConn.getConnection();

            String sql = "SELECT DATE(timestamp) AS day, COUNT(*) AS cnt "
                       + "FROM " + Constants.TABLE_INCIDENTS
                       + " WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) "
                       + "  AND ai_decision != 'SAFE' "
                       + "GROUP BY DATE(timestamp) ORDER BY day ASC";

            try (PreparedStatement ps = conn.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String dateStr = rs.getString("day");
                    int    count   = rs.getInt("cnt");
                    dataset.addValue(count, "Threats", dateStr);
                }
            }
        } catch (Exception e) {
            System.err.println("[ChartBuilder] DB query failed: " + e.getMessage());
        }

        // Fallback: sample data if nothing in DB yet
        if (dataset.getRowCount() == 0) {
            DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MM-dd");
            LocalDate today = LocalDate.now();
            int[] sampleData = {2, 5, 1, 8, 3, 0, 4};
            for (int i = 6; i >= 0; i--) {
                String day = today.minusDays(i).format(fmt);
                dataset.addValue(sampleData[6 - i], "Threats", day);
            }
        }

        JFreeChart chart = ChartFactory.createBarChart(
            "Threats — Last 7 Days", "Date", "Count",
            dataset, PlotOrientation.VERTICAL, false, true, false
        );

        // Apply dark theme
        chart.setBackgroundPaint(new Color(13, 13, 26));
        chart.getTitle().setPaint(Color.WHITE);
        chart.getTitle().setFont(new Font("Segoe UI", Font.BOLD, 14));

        CategoryPlot plot = chart.getCategoryPlot();
        // Dark plot background
        plot.setBackgroundPaint(new Color(20, 20, 40));
        plot.setOutlineVisible(false);
        plot.setRangeGridlinePaint(new Color(30, 45, 90));
        plot.setDomainGridlinesVisible(false);

        // Axis colors
        CategoryAxis domainAxis = plot.getDomainAxis();
        domainAxis.setTickLabelPaint(new Color(107, 125, 179));
        domainAxis.setAxisLinePaint(new Color(30, 45, 90));
        domainAxis.setLabelPaint(Color.WHITE);

        NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
        rangeAxis.setTickLabelPaint(new Color(107, 125, 179));
        rangeAxis.setAxisLinePaint(new Color(30, 45, 90));
        rangeAxis.setLabelPaint(Color.WHITE);

        // Bar gradient renderer
        GradientBarPainter painter = new GradientBarPainter(0.1, 0.2, 0.8);
        BarRenderer renderer = (BarRenderer) plot.getRenderer();
        renderer.setBarPainter(painter);
        renderer.setSeriesPaint(0, new GradientPaint(
            0, 0, new Color(0, 212, 255),
            0, 100, new Color(123, 47, 255)));
        renderer.setShadowVisible(false);
        renderer.setMaximumBarWidth(0.5);

        return chart;
    }

    // ── Wrapper ───────────────────────────────────────────────────────────

    /**
     * Wraps a JFreeChart in a ChartPanel with the preferred dashboard size.
     *
     * @param chart the chart to wrap
     * @return ChartPanel sized 400×300
     */
    public static ChartPanel wrapInPanel(JFreeChart chart) {
        ChartPanel cp = new ChartPanel(chart);
        cp.setPreferredSize(new Dimension(400, 280));
        cp.setBackground(BG_DARK);
        cp.setBorder(null);
        return cp;
    }
}
