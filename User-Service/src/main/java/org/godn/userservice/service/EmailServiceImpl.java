package org.godn.userservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender mailSender;
    private final String fromEmail;

    public EmailServiceImpl(JavaMailSender mailSender,
                            @Value("${spring.mail.from}") String fromEmail) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail; // <-- Save the "from" address
    }

    /**
     * Sends an email with a 6-digit verification OTP.
     */
    @Override
    public void sendVerificationEmail(String to, String token) {
        String subject = "Chikitsalaya - Email Verification";

        String messageText = "Thank you for registering for Chikitsalaya.\n\n" +
                "Your email verification code is: " + token + "\n\n" +
                "This code will expire in 15 minutes.";

        sendSimpleEmail(to, subject, messageText);
    }

    /**
     * Sends an email with a 6-digit password reset OTP.
     */
    @Override
    public void sendPasswordResetEmail(String to, String token) {
        String subject = "Chikitsalaya - Password Reset Request";

        String messageText = "You have requested to reset your password.\n\n" +
                "Your password reset code is: " + token + "\n\n" +
                "This code will expire in 15 minutes.\n" +
                "If you did not request this, please ignore this email.";

        sendSimpleEmail(to, subject, messageText);
    }

    /**
     * Helper method to create and send a simple text email.
     */
    private void sendSimpleEmail(String to, String subject, String text) {
        SimpleMailMessage email = new SimpleMailMessage();

        email.setFrom(fromEmail); // <-- ✅ THE FIX: Set the "From" address
        email.setTo(to);
        email.setSubject(subject);
        email.setText(text);
        mailSender.send(email);
    }
}