package com.phishguard.email;

import jakarta.mail.Address;
import jakarta.mail.BodyPart;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.internet.InternetAddress;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * PhishGuard - EmailParser.java
 * -------------------------------------------------
 * Parses a Jakarta Mail {@link Message} into a clean {@link ParsedEmail}
 * data object, handling plain text, HTML, and MIME multipart structures.
 *
 * Design decisions:
 *  - Plain text body is preferred over HTML (easier for NLP analysis)
 *  - On parse failure, returns a sentinel ParsedEmail with "parse-error" subject
 *    so the pipeline can still log the event and continue
 *  - HTML stripping is a simple regex approach (sufficient for URL extraction)
 */
public final class EmailParser {

    private EmailParser() {}

    // ────────────────────────────────────────────────────────────────────────
    // Inner class: ParsedEmail
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Plain data object representing a parsed email message.
     * All fields are public for simplicity in this academic project.
     */
    public static class ParsedEmail {

        /** Actual email address from the From: header */
        public String senderEmail    = "unknown";
        /** Display name portion of the From: header (null if absent) */
        public String displayName    = null;
        /** Email subject line */
        public String subject        = "";
        /** Plain-text version of the email body (preferred for NLP) */
        public String bodyText       = "";
        /** HTML version of the email body (fallback) */
        public String bodyHtml       = "";
        /** All URLs extracted from bodyText by URLExtractor */
        public List<String> urls     = new ArrayList<>();
        /** Timestamp when the email was received at the server */
        public Date receivedDate     = null;
        /** Message-ID header value */
        public String messageId      = "";

        @Override
        public String toString() {
            return String.format("ParsedEmail{from='%s', subject='%s', urls=%d}",
                senderEmail, subject, urls.size());
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Public API
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Parses a Jakarta Mail Message and returns a populated ParsedEmail.
     *
     * Extracts: sender email + display name, subject, plain/HTML body,
     * all URLs from the body, and received date.
     *
     * @param message a Jakarta Mail Message from an open IMAP folder
     * @return populated ParsedEmail; sentinel with "parse-error" on failure
     */
    public static ParsedEmail parse(Message message) {
        ParsedEmail email = new ParsedEmail();

        try {
            // ── Step 1: Extract sender ──────────────────────────────────
            Address[] fromAddresses = message.getFrom();
            if (fromAddresses != null && fromAddresses.length > 0) {
                if (fromAddresses[0] instanceof InternetAddress) {
                    InternetAddress from = (InternetAddress) fromAddresses[0];
                    email.senderEmail = from.getAddress() != null
                        ? from.getAddress().toLowerCase().trim()
                        : "unknown";
                    email.displayName = from.getPersonal();
                    // If no display name, fall back to the email address itself
                    if (email.displayName == null || email.displayName.isBlank()) {
                        email.displayName = email.senderEmail;
                    }
                }
            }

            // ── Step 2: Extract subject ─────────────────────────────────
            String subj = message.getSubject();
            email.subject = (subj != null) ? subj.trim() : "";

            // ── Step 3: Extract body ────────────────────────────────────
            Object content = message.getContent();
            if (content instanceof String) {
                // Simple single-part text message
                email.bodyText = (String) content;
            } else if (content instanceof Multipart) {
                extractFromMultipart((Multipart) content, email);
                // If only HTML was found, convert it to plain text for NLP
                if ((email.bodyText == null || email.bodyText.isBlank())
                        && email.bodyHtml != null && !email.bodyHtml.isBlank()) {
                    email.bodyText = stripHtml(email.bodyHtml);
                }
            }

            if (email.bodyText == null) email.bodyText = "";
            if (email.bodyHtml  == null) email.bodyHtml  = "";

            // ── Step 4: Extract URLs from body ──────────────────────────
            email.urls = URLExtractor.extract(email.bodyText);
            // Also scan HTML body for URLs missed in plain text
            if (!email.bodyHtml.isBlank()) {
                List<String> htmlUrls = URLExtractor.extract(email.bodyHtml);
                for (String u : htmlUrls) {
                    if (!email.urls.contains(u)) {
                        email.urls.add(u);
                    }
                }
            }

            // ── Step 5: Set dates and message ID ────────────────────────
            email.receivedDate = message.getReceivedDate();
            String[] msgIds = message.getHeader("Message-ID");
            if (msgIds != null && msgIds.length > 0) {
                email.messageId = msgIds[0];
            }

        } catch (Exception e) {
            // Return a sentinel so the pipeline can log and continue
            System.err.println("[EmailParser] Failed to parse message: " + e.getMessage());
            email.senderEmail = "unknown";
            email.subject     = "parse-error";
            email.bodyText    = "";
            email.urls        = new ArrayList<>();
        }

        return email;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Recursively traverses a MIME Multipart to extract text/plain and text/html parts.
     * Prefers the first text/plain part found; stores text/html as fallback.
     *
     * @param multipart the MIME multipart object to traverse
     * @param email     the ParsedEmail being populated
     */
    private static void extractFromMultipart(Multipart multipart, ParsedEmail email) {
        try {
            int count = multipart.getCount();
            for (int i = 0; i < count; i++) {
                BodyPart part = multipart.getBodyPart(i);
                String contentType = part.getContentType().toLowerCase();

                if (contentType.startsWith("text/plain") && email.bodyText.isBlank()) {
                    // Prefer plain text — store only the first plain part
                    Object c = part.getContent();
                    email.bodyText = c instanceof String ? (String) c : c.toString();

                } else if (contentType.startsWith("text/html") && email.bodyHtml.isBlank()) {
                    Object c = part.getContent();
                    email.bodyHtml = c instanceof String ? (String) c : c.toString();

                } else if (part.getContent() instanceof Multipart) {
                    // Recurse into nested MIME parts (e.g., multipart/alternative)
                    extractFromMultipart((Multipart) part.getContent(), email);
                }
                // Attachments (application/*, image/*, etc.) are intentionally ignored
            }
        } catch (Exception e) {
            System.err.println("[EmailParser] Error in multipart extraction: " + e.getMessage());
        }
    }

    /**
     * Strips HTML tags from a string to produce readable plain text.
     * Used when no text/plain part is available but text/html is.
     *
     * @param html raw HTML string
     * @return plain text approximation
     */
    private static String stripHtml(String html) {
        if (html == null) return "";
        return html
            .replaceAll("<[^>]*>", " ")   // Remove all HTML tags
            .replaceAll("&nbsp;", " ")     // Decode common HTML entities
            .replaceAll("&amp;",  "&")
            .replaceAll("&lt;",   "<")
            .replaceAll("&gt;",   ">")
            .replaceAll("&quot;", "\"")
            .replaceAll("\\s+",   " ")     // Collapse whitespace
            .trim();
    }
}
