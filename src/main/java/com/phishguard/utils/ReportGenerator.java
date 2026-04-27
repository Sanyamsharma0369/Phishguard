package com.phishguard.utils;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.phishguard.database.DBConnection;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ReportGenerator {

    private static final BaseColor RED    = new BaseColor(248, 81, 73);
    private static final BaseColor ORANGE = new BaseColor(210, 153, 34);
    private static final BaseColor GREEN  = new BaseColor(63, 185, 80);
    private static final BaseColor DARK   = new BaseColor(22, 27, 34);
    private static final BaseColor LIGHT  = new BaseColor(230, 237, 243);

    public static byte[] generateReport() throws Exception {
        Document doc = new Document(PageSize.A4, 40, 40, 60, 40);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfWriter writer = PdfWriter.getInstance(doc, out);

        doc.open();

        // ── Header ──────────────────────────────────────────────────────
        Font titleFont  = new Font(Font.FontFamily.HELVETICA, 22, Font.BOLD, LIGHT);
        Font subFont    = new Font(Font.FontFamily.HELVETICA, 11, Font.NORMAL, ORANGE);
        Font headerFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD, LIGHT);
        Font bodyFont   = new Font(Font.FontFamily.HELVETICA, 9,  Font.NORMAL, LIGHT);
        Font redFont    = new Font(Font.FontFamily.HELVETICA, 9,  Font.BOLD, RED);
        Font greenFont  = new Font(Font.FontFamily.HELVETICA, 9,  Font.BOLD, GREEN);
        Font orangeFont = new Font(Font.FontFamily.HELVETICA, 9,  Font.BOLD, ORANGE);

        // Title block
        PdfPTable header = new PdfPTable(1);
        header.setWidthPercentage(100);
        PdfPCell titleCell = new PdfPCell();
        titleCell.setBackgroundColor(DARK);
        titleCell.setPadding(20);
        titleCell.setBorder(Rectangle.NO_BORDER);
        titleCell.addElement(new Paragraph("🛡️  PhishGuard Security Report", titleFont));
        titleCell.addElement(new Paragraph("Generated: " +
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd MMM yyyy, hh:mm a")), subFont));
        header.addCell(titleCell);
        doc.add(header);
        doc.add(Chunk.NEWLINE);

        // ── Stats from DB ────────────────────────────────────────────────
        var stats = DBConnection.getInstance().getStats();
        int total   = (int) ((Number) stats.getOrDefault("totalIncidents", 0)).intValue();
        int threats = (int) ((Number) stats.getOrDefault("threats", 0)).intValue();
        int blocked = (int) ((Number) stats.getOrDefault("blocked", 0)).intValue();
        int safe    = (int) ((Number) stats.getOrDefault("safe", 0)).intValue();
        double avg  = (double) ((Number) stats.getOrDefault("avgRisk", 0.0)).doubleValue();

        // KPI Row
        PdfPTable kpis = new PdfPTable(5);
        kpis.setWidthPercentage(100);
        kpis.setSpacingBefore(10);
        addKpiCell(kpis, "Total Scanned", String.valueOf(total), LIGHT, headerFont, bodyFont);
        addKpiCell(kpis, "Threats",       String.valueOf(threats), RED, headerFont, redFont);
        addKpiCell(kpis, "Blocked",       String.valueOf(blocked), RED, headerFont, redFont);
        addKpiCell(kpis, "Safe",          String.valueOf(safe), GREEN, headerFont, greenFont);
        addKpiCell(kpis, "Avg Risk",      String.format("%.3f", avg), ORANGE, headerFont, orangeFont);
        doc.add(kpis);
        doc.add(Chunk.NEWLINE);

        // ── Section: Recent Incidents ────────────────────────────────────
        Paragraph sec = new Paragraph("Recent Incidents (Last 50)",
            new Font(Font.FontFamily.HELVETICA, 13, Font.BOLD, LIGHT));
        sec.setSpacingBefore(10);
        doc.add(sec);
        doc.add(new LineSeparator(0.5f, 100, ORANGE, Element.ALIGN_CENTER, -2));
        doc.add(Chunk.NEWLINE);

        // Table
        PdfPTable table = new PdfPTable(new float[]{3, 2, 1, 1.2f});
        table.setWidthPercentage(100);
        String[] cols = {"URL / Target", "Sender", "Risk Score", "Decision"};
        for (String col : cols) {
            PdfPCell c = new PdfPCell(new Phrase(col,
                new Font(Font.FontFamily.HELVETICA, 9, Font.BOLD, LIGHT)));
            c.setBackgroundColor(new BaseColor(33, 38, 45));
            c.setPadding(6); c.setBorderColor(new BaseColor(48, 54, 61));
            table.addCell(c);
        }

        var incidents = DBConnection.getInstance().getRecentIncidentsForReport(50);
        boolean alt = false;
        for (var inc : incidents) {
            BaseColor bg = alt ? new BaseColor(22,27,34) : new BaseColor(27,32,39);
            alt = !alt;

            String url    = inc.getOrDefault("url", "").toString();
            String sender = inc.getOrDefault("sender", "—").toString();
            String score  = inc.getOrDefault("riskScore", "—").toString();
            String dec    = inc.getOrDefault("decision", "—").toString();

            // Truncate URL
            if (url.length() > 55) url = url.substring(0, 52) + "...";

            Font decFont = dec.equals("HIGH_RISK") ? redFont :
                           dec.equals("SUSPICIOUS") ? orangeFont : greenFont;

            addTableCell(table, url,    bg, bodyFont,  6);
            addTableCell(table, sender, bg, bodyFont,  6);
            addTableCell(table, score,  bg, bodyFont,  6);
            PdfPCell dc = new PdfPCell(new Phrase(dec, decFont));
            dc.setBackgroundColor(bg); dc.setPadding(6);
            dc.setBorderColor(new BaseColor(48,54,61));
            table.addCell(dc);
        }
        doc.add(table);

        // ── Footer ────────────────────────────────────────────────────────
        doc.add(Chunk.NEWLINE);
        Paragraph footer = new Paragraph(
            "PhishGuard v1.0 — AI-Powered Email Phishing Detection System\n" +
            "Report generated on " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd-MM-yyyy")),
            new Font(Font.FontFamily.HELVETICA, 8, Font.ITALIC, new BaseColor(100,110,120)));
        footer.setAlignment(Element.ALIGN_CENTER);
        doc.add(footer);

        doc.close();
        return out.toByteArray();
    }

    private static void addKpiCell(PdfPTable t, String label, String val,
                                    BaseColor valColor, Font hf, Font vf) {
        PdfPCell c = new PdfPCell();
        c.setBackgroundColor(new BaseColor(27,32,39));
        c.setPadding(12); c.setBorderColor(new BaseColor(48,54,61));
        c.addElement(new Paragraph(label, new Font(Font.FontFamily.HELVETICA, 8, Font.NORMAL, new BaseColor(139,148,158))));
        c.addElement(new Paragraph(val, new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD, valColor)));
        t.addCell(c);
    }

    private static void addTableCell(PdfPTable t, String text, BaseColor bg, Font f, int pad) {
        PdfPCell c = new PdfPCell(new Phrase(text, f));
        c.setBackgroundColor(bg); c.setPadding(pad);
        c.setBorderColor(new BaseColor(48,54,61));
        t.addCell(c);
    }
}
