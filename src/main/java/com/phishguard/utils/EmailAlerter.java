package com.phishguard.utils;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;

public class EmailAlerter {

    public static void sendAlert(String subject, String body) {
        try {
            ConfigLoader cfg = ConfigLoader.getInstance();
            String user = cfg.get("email.user");
            String pass = cfg.get("email.password");

            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");

            Session session = Session.getInstance(props, new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(user, pass);
                }
            });

            Message msg = new MimeMessage(session);
            msg.setFrom(new InternetAddress(user));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(user));
            msg.setSubject(subject);
            msg.setText(body);

            Transport.send(msg);
            System.out.println("[Alert] Email sent: " + subject);
        } catch (Exception e) {
            System.err.println("[Alert] Failed to send email: " + e.getMessage());
        }
    }
}
