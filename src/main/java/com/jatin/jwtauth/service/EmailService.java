package com.jatin.jwtauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * EmailService — thin wrapper around JavaMailSender.
 *
 * Key learning points:
 *  1. JavaMailSender is auto-configured by Spring Boot when
 *     spring.mail.* properties are present.
 *  2. Using SimpleMailMessage keeps the implementation minimal —
 *     a richer MimeMessage / Thymeleaf template can replace it later.
 *  3. The bean is mocked in tests via @MockBean, so no real SMTP server
 *     is needed during CI/CD.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@jwtauth.local}")
    private String fromAddress;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    /**
     * Send an email-verification link to the newly registered user.
     *
     * @param toEmail   recipient address
     * @param username  user's username (used in the message body)
     * @param token     the one-time verification UUID
     */
    public void sendVerificationEmail(String toEmail, String username, String token) {
        String link = baseUrl + "/api/auth/verify?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("Verify your email — JWT Auth API");
        message.setText(
                "Hi " + username + ",\n\n" +
                "Please verify your email address by clicking the link below:\n\n" +
                link + "\n\n" +
                "This link is valid until you register with a different email or request a new one.\n\n" +
                "If you did not create this account, you can safely ignore this email.\n\n" +
                "— JWT Auth API"
        );

        mailSender.send(message);
        log.info("EmailVerification: sent to {} for user '{}'", toEmail, username);
    }

    /**
     * Send a password-reset link to the user's registered email.
     *
     * @param toEmail   recipient address
     * @param username  user's username (used in the message body)
     * @param token     the one-time reset UUID
     */
    public void sendPasswordResetEmail(String toEmail, String username, String token) {
        String link = baseUrl + "/api/auth/reset-password?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("Reset your password — JWT Auth API");
        message.setText(
                "Hi " + username + ",\n\n" +
                "We received a request to reset your password. Click the link below to choose a new one:\n\n" +
                link + "\n\n" +
                "This link expires in 1 hour. If you did not request a password reset you can safely ignore this email.\n\n" +
                "— JWT Auth API"
        );

        mailSender.send(message);
        log.info("PasswordReset: sent reset email to {} for user '{}'", toEmail, username);
    }
}
