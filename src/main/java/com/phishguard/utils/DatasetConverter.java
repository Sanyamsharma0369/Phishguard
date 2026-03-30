package com.phishguard.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;

/**
 * PhishGuard - DatasetConverter.java
 * -------------------------------------------------
 * Converts the external PhiUSIIL CSV dataset to Weka ARFF format.
 * Usage: java DatasetConverter input.csv output.arff
 */
public class DatasetConverter {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: DatasetConverter <input.csv> <output.arff>");
            return;
        }
        try {
            convert(args[0], args[1]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void convert(String csvPath, String arffOutputPath) throws Exception {
        System.out.println("[Converter] Reading from " + csvPath);

        try (BufferedReader br = new BufferedReader(new FileReader(csvPath));
             BufferedWriter bw = new BufferedWriter(new FileWriter(arffOutputPath))) {

            // Write ARFF Header
            bw.write("@RELATION PhishGuardURLs\n\n");
            bw.write("@ATTRIBUTE url_length NUMERIC\n");
            bw.write("@ATTRIBUTE has_https NUMERIC\n");
            bw.write("@ATTRIBUTE has_ip_address NUMERIC\n");
            bw.write("@ATTRIBUTE suspicious_keyword_count NUMERIC\n");
            bw.write("@ATTRIBUTE dot_count NUMERIC\n");
            bw.write("@ATTRIBUTE special_char_count NUMERIC\n");
            bw.write("@ATTRIBUTE entropy NUMERIC\n");
            bw.write("@ATTRIBUTE subdomain_count NUMERIC\n");
            bw.write("@ATTRIBUTE class {legitimate,phishing}\n\n");
            bw.write("@DATA\n");

            String headerLine = br.readLine(); // skip header
            if (headerLine == null) return;

            String[] headers = headerLine.split(",");
            
            // Map column indices (approximation, dependent on actual PhiUSIIL structure)
            int idxLen = find(headers, "URLLength");
            int idxHttps = find(headers, "IsHTTPS");
            int idxIp = find(headers, "URLCharProb"); // fallback for proxy
            int idxSub = find(headers, "NoOfSubDomain");
            int idxEnt = find(headers, "URLEntropy");
            int idxKw = find(headers, "NoOfSuspiciousKeywords"); // or similar
            int idxDots = find(headers, "NoOfDots");
            int idxChars = find(headers, "NoOfSpecialChars");
            int idxLabel = find(headers, "label");

            int count = 0;
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length <= Math.max(idxLen, idxLabel)) continue;

                try {
                    double length = (idxLen >= 0) ? Double.parseDouble(parts[idxLen]) / 200.0 : 0.0;
                    double https = (idxHttps >= 0) ? Double.parseDouble(parts[idxHttps]) : 0.0;
                    double ip = (idxIp >= 0) ? (Double.parseDouble(parts[idxIp]) > 0.05 ? 1.0 : 0.0) : 0.0;
                    double sub = (idxSub >= 0) ? Double.parseDouble(parts[idxSub]) / 5.0 : 0.0;
                    double ent = (idxEnt >= 0) ? Double.parseDouble(parts[idxEnt]) : 0.0;
                    double kw = (idxKw >= 0) ? Double.parseDouble(parts[idxKw]) / 10.0 : 0.0;
                    double dots = (idxDots >= 0) ? Double.parseDouble(parts[idxDots]) / 10.0 : 0.0;
                    double chars = (idxChars >= 0) ? Double.parseDouble(parts[idxChars]) / 20.0 : 0.0;
                    
                    String label = "legitimate";
                    if (idxLabel >= 0) {
                        if (parts[idxLabel].trim().equals("1")) label = "phishing";
                    }

                    bw.write(String.format("%.4f,%.1f,%.1f,%.4f,%.4f,%.4f,%.4f,%.4f,%s\n",
                            Math.min(1.0, length), https, ip, Math.min(1.0, kw), 
                            Math.min(1.0, dots), Math.min(1.0, chars), ent, Math.min(1.0, sub), label));
                    
                    count++;
                    if (count % 10000 == 0) {
                        System.out.println("[Converter] Converted " + count + " records...");
                    }
                } catch (NumberFormatException ignored) {
                    // Skip malformed rows
                }
            }
            System.out.println("[Converter] Converted " + count + " total records to " + arffOutputPath);
        }
    }

    private static int find(String[] headers, String name) {
        for (int i = 0; i < headers.length; i++) {
            if (headers[i].equalsIgnoreCase(name)) return i;
        }
        return -1;
    }
}
