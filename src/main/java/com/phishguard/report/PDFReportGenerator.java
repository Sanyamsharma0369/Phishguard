package com.phishguard.report;

import com.phishguard.engine.RiskScorer;
import com.phishguard.utils.Constants;
import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Chunk;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Font;
import com.itextpdf.text.FontFactory;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.File;
import java.io.FileOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PhishGuard - PDFReportGenerator.java
 * -------------------------------------------------
 * Generates multi-page forensic PDF reports using iText 5 API.
 *
 * Report structure:
 *   Page 1  — Cover (title, generated timestamp, summary stats)
 *   Page 2  — Summary statistics table + brand analysis
 *   Page 3+ — Individual HIGH_RISK incident details
 *   Last    — Footer / disclaimer
 *
 * IMPORTANT: Uses iText 5 (com.itextpdf:itextpdf:5.5.13.3), NOT iText 7.
 */
public final class PDFReportGenerator {

    private PDFReportGenerator() {}

    // ── Color palette ─────────────────────────────────────────────────────
    private static final BaseColor COLOR_HEADER  = new BaseColor(0x1e, 0x1e, 0x2e); // dark navy
    private static final BaseColor COLOR_ACCENT  = new BaseColor(0x4f, 0x8e, 0xf7); // blue
    private static final BaseColor COLOR_SAFE    = new BaseColor(0x27, 0xae, 0x60); // green
    private static final BaseColor COLOR_WARN    = new BaseColor(0xd3, 0x84, 0x00); // orange
    private static final BaseColor COLOR_RISK    = new BaseColor(0xc0, 0x39, 0x2b); // red
    private static final BaseColor COLOR_ROW_ALT = new BaseColor(0xf2, 0xf2, 0xf8); // light gray
    private static final BaseColor COLOR_WHITE   = BaseColor.WHITE;

    // ── Fonts ─────────────────────────────────────────────────────────────
    private static final Font FONT_TITLE   = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 22, COLOR_WHITE);
    private static final Font FONT_H2      = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, COLOR_ACCENT);
    private static final Font FONT_H3      = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, BaseColor.DARK_GRAY);
    private static final Font FONT_BODY    = FontFactory.getFont(FontFactory.HELVETICA, 10, BaseColor.DARK_GRAY);
    private static final Font FONT_TH      = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, COLOR_WHITE);
    private static final Font FONT_RISK    = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, COLOR_RISK);
    private static final Font FONT_WARN    = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, COLOR_WARN);
    private static final Font FONT_SAFE_F  = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, COLOR_SAFE);

    private static final DateTimeFormatter DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Generates a PDF forensic report and saves it to a temp file.
     *
     * @param incidents list of RiskScorer objects (from IncidentDAO.getRecentIncidents())
     * @return File pointing to the generated PDF
     * @throws Exception on iText or IO errors (caller shows error dialog)
     */
    public static File generateReport(List<RiskScorer> incidents) throws Exception {
        File outFile = File.createTempFile("PhishGuard_Report_", ".pdf");

        Document doc = new Document(PageSize.A4, 50, 50, 60, 60);
        PdfWriter.getInstance(doc, new FileOutputStream(outFile));
        doc.open();

        addCoverPage(doc, incidents);
        doc.newPage();
        addSummaryPage(doc, incidents);

        // Incident detail pages — only HIGH_RISK and SUSPICIOUS
        List<RiskScorer> threats = incidents.stream()
            .filter(s -> !Constants.DECISION_SAFE.equals(s.decision))
            .toList();

        if (!threats.isEmpty()) {
            doc.newPage();
            addHeader(doc, "Incident Details");
            for (RiskScorer s : threats) {
                addIncidentBlock(doc, s);
            }
        }

        doc.newPage();
        addFooterPage(doc);

        doc.close();
        System.out.println("[PDFReport] Generated: " + outFile.getAbsolutePath());
        return outFile;
    }

    // ── Page builders ─────────────────────────────────────────────────────

    private static void addCoverPage(Document doc, List<RiskScorer> incidents)
            throws DocumentException {
        // Dark header band
        PdfPTable banner = new PdfPTable(1);
        banner.setWidthPercentage(100);
        PdfPCell bannerCell = new PdfPCell();
        bannerCell.setBackgroundColor(COLOR_HEADER);
        bannerCell.setPadding(30);
        bannerCell.setBorder(Rectangle.NO_BORDER);

        Paragraph title = new Paragraph("PhishGuard", FONT_TITLE);
        title.setAlignment(Element.ALIGN_CENTER);
        bannerCell.addElement(title);

        Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA, 13, COLOR_ACCENT);
        Paragraph subtitle = new Paragraph("Security Incident Report", subtitleFont);
        subtitle.setAlignment(Element.ALIGN_CENTER);
        bannerCell.addElement(subtitle);

        banner.addCell(bannerCell);
        doc.add(banner);

        doc.add(new Paragraph(" "));
        doc.add(new Paragraph(" "));

        // Metadata
        Font metaFont = FontFactory.getFont(FontFactory.HELVETICA, 12, BaseColor.DARK_GRAY);
        doc.add(centeredPara("Generated: " + LocalDateTime.now().format(DT_FMT), metaFont));
        doc.add(centeredPara("System Version: " + Constants.APP_VERSION, metaFont));
        doc.add(centeredPara("Total Incidents Analyzed: " + incidents.size(), metaFont));

        long threats = incidents.stream()
            .filter(s -> !Constants.DECISION_SAFE.equals(s.decision)).count();
        doc.add(centeredPara("Threats Detected: " + threats, metaFont));

        doc.add(new Paragraph(" "));
        doc.add(horizontalLine());
        doc.add(new Paragraph(" "));

        Font noteFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 10, BaseColor.GRAY);
        doc.add(centeredPara(
            "This report is automatically generated by PhishGuard v" + Constants.APP_VERSION
            + " for forensic analysis purposes.", noteFont));
    }

    private static void addSummaryPage(Document doc, List<RiskScorer> incidents)
            throws DocumentException {
        addHeader(doc, "Summary Statistics");

        int safe      = (int) incidents.stream().filter(s -> Constants.DECISION_SAFE.equals(s.decision)).count();
        int suspicious= (int) incidents.stream().filter(s -> Constants.DECISION_SUSPICIOUS.equals(s.decision)).count();
        int highRisk  = (int) incidents.stream().filter(s -> Constants.DECISION_HIGH_RISK.equals(s.decision)).count();
        int blocked   = (int) incidents.stream().filter(s -> "BLOCKED".equals(s.actionTaken)).count();
        double avgScore = incidents.isEmpty() ? 0.0
            : incidents.stream().mapToDouble(s -> s.finalScore).average().orElse(0.0);

        PdfPTable stats = new PdfPTable(2);
        stats.setWidthPercentage(70);
        stats.setSpacingBefore(10);
        stats.setSpacingAfter(20);

        addStatRow(stats, "Total Incidents",       String.valueOf(incidents.size()));
        addStatRow(stats, "Safe URLs",             String.valueOf(safe));
        addStatRow(stats, "Suspicious URLs",       String.valueOf(suspicious));
        addStatRow(stats, "High Risk URLs",        String.valueOf(highRisk));
        addStatRow(stats, "Blocked URLs",          String.valueOf(blocked));
        addStatRow(stats, "Average Risk Score",    String.format("%.4f", avgScore));
        doc.add(stats);

        // Brand targeting breakdown
        addHeader(doc, "Brand Impersonation Targets");
        Map<String, Integer> brandCount = new HashMap<>();
        for (RiskScorer s : incidents) {
            if (s.visualBrandDetected != null && !s.visualBrandDetected.isBlank()
                    && !"Unknown".equals(s.visualBrandDetected)) {
                brandCount.merge(s.visualBrandDetected, 1, (a, b) -> a + b);
            }
        }

        if (brandCount.isEmpty()) {
            doc.add(new Paragraph("No brand impersonation detected.", FONT_BODY));
        } else {
            PdfPTable brandTable = new PdfPTable(2);
            brandTable.setWidthPercentage(60);
            brandTable.setSpacingBefore(10);
            addTableHeader(brandTable, "Brand", "Times Targeted");
            boolean alt = false;
            for (Map.Entry<String, Integer> e : brandCount.entrySet()) {
                PdfPCell c1 = bodyCell(e.getKey(), alt);
                PdfPCell c2 = bodyCell(String.valueOf(e.getValue()), alt);
                brandTable.addCell(c1);
                brandTable.addCell(c2);
                alt = !alt;
            }
            doc.add(brandTable);
        }
    }

    private static void addIncidentBlock(Document doc, RiskScorer s)
            throws DocumentException {
        doc.add(new Paragraph(" "));

        // Decision color
        Font decFont = Constants.DECISION_HIGH_RISK.equals(s.decision) ? FONT_RISK
                     : Constants.DECISION_SUSPICIOUS.equals(s.decision) ? FONT_WARN
                     : FONT_SAFE_F;

        Paragraph decPara = new Paragraph("[" + s.decision + "] " + s.url, decFont);
        doc.add(decPara);

        PdfPTable t = new PdfPTable(new float[]{2f, 3f});
        t.setWidthPercentage(100);
        t.setSpacingBefore(5);
        t.setSpacingAfter(5);

        addDetailRow(t, "Sender",           s.emailSender   != null ? s.emailSender : "—");
        addDetailRow(t, "Subject",          s.emailSubject  != null ? s.emailSubject : "—");
        addDetailRow(t, "Final Score",      String.format("%.4f", s.finalScore));
        addDetailRow(t, "Action",           s.actionTaken   != null ? s.actionTaken : "—");
        addDetailRow(t, "Sender Score",     String.format("%.3f", s.senderScore));
        addDetailRow(t, "Text NLP Score",   String.format("%.3f", s.textScore));
        addDetailRow(t, "AI Model Score",   String.format("%.3f", s.aiModelScore));
        addDetailRow(t, "Threat Intel",     String.format("%.3f", s.threatIntelScore));
        addDetailRow(t, "Visual Score",     String.format("%.3f", s.visualScore));
        if (s.visualBrandDetected != null && !s.visualBrandDetected.isBlank()) {
            addDetailRow(t, "Brand Detected", s.visualBrandDetected);
        }
        doc.add(t);
        doc.add(horizontalLine());
    }

    private static void addFooterPage(Document doc) throws DocumentException {
        addHeader(doc, "Disclaimer");
        doc.add(new Paragraph(
            "This report was generated automatically by PhishGuard v" + Constants.APP_VERSION + ".\n"
            + "All analysis results are based on AI-assisted heuristics and third-party threat "
            + "intelligence APIs (PhishTank, VirusTotal). Results should be reviewed by a qualified "
            + "security professional before taking enforcement action.\n\n"
            + "Generated: " + LocalDateTime.now().format(DT_FMT),
            FONT_BODY));
    }

    // ── Table helpers ─────────────────────────────────────────────────────

    private static void addTableHeader(PdfPTable table, String... headers) {
        for (String h : headers) {
            PdfPCell cell = new PdfPCell(new Phrase(h, FONT_TH));
            cell.setBackgroundColor(COLOR_HEADER);
            cell.setPadding(6);
            cell.setBorderColor(BaseColor.LIGHT_GRAY);
            table.addCell(cell);
        }
    }

    private static void addStatRow(PdfPTable table, String label, String value) {
        PdfPCell labelCell = new PdfPCell(new Phrase(label, FONT_BODY));
        labelCell.setPadding(5);
        labelCell.setBorderColor(BaseColor.LIGHT_GRAY);
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(new Phrase(value,
            FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, BaseColor.DARK_GRAY)));
        valueCell.setPadding(5);
        valueCell.setBorderColor(BaseColor.LIGHT_GRAY);
        table.addCell(valueCell);
    }

    private static void addDetailRow(PdfPTable t, String key, String val) {
        PdfPCell k = new PdfPCell(new Phrase(key, FONT_H3));
        k.setPadding(4);
        k.setBackgroundColor(COLOR_ROW_ALT);
        k.setBorderColor(BaseColor.LIGHT_GRAY);
        t.addCell(k);

        PdfPCell v = new PdfPCell(new Phrase(val, FONT_BODY));
        v.setPadding(4);
        v.setBorderColor(BaseColor.LIGHT_GRAY);
        t.addCell(v);
    }

    private static PdfPCell bodyCell(String text, boolean alt) {
        PdfPCell cell = new PdfPCell(new Phrase(text, FONT_BODY));
        cell.setPadding(5);
        cell.setBorderColor(BaseColor.LIGHT_GRAY);
        if (alt) cell.setBackgroundColor(COLOR_ROW_ALT);
        return cell;
    }

    private static void addHeader(Document doc, String text) throws DocumentException {
        doc.add(new Paragraph(" "));
        Paragraph p = new Paragraph(text, FONT_H2);
        p.setSpacingAfter(8);
        doc.add(p);
    }

    private static Paragraph centeredPara(String text, Font font) {
        Paragraph p = new Paragraph(text, font);
        p.setAlignment(Element.ALIGN_CENTER);
        p.setSpacingAfter(6);
        return p;
    }

    private static Paragraph horizontalLine() {
        com.itextpdf.text.pdf.draw.LineSeparator ls =
            new com.itextpdf.text.pdf.draw.LineSeparator();
        ls.setLineColor(BaseColor.LIGHT_GRAY);
        Paragraph line = new Paragraph(new Chunk(ls));
        line.setSpacingBefore(5);
        line.setSpacingAfter(5);
        return line;
    }
}
