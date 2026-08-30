package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.PasswordResetToken;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * PasswordResetService — manages the forgot-password / reset-password lifecycle.
 *
 * Key learning points:
 *  1. requestReset() always returns HTTP 204 regardless of whether the email is found.
 *     This prevents user-enumeration attacks (attacker can't tell if an email exists).
 *  2. Tokens expire after 1 hour and are single-use (used=true after redemption).
 *  3. resetPassword() validates: token exists, not expired, not already used.
 *  4. After a successful reset, all existing refresh tokens for the user are revoked
 *     (via RefreshTokenService) so previously stolen sessions are invalidated.
 *  5. @Scheduled cleanup purges expired/used rows every hour.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final long EXPIRY_HOURS = 1L;

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    /**
     * Initiate a password reset.  Silently no-ops when the email is unknown
     * to prevent user-enumeration.
     */
    @Transactional
    public void requestReset(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            // Revoke any previous reset token for this user
            tokenRepository.deleteByUser(user);

            String rawToken = UUID.randomUUID().toString();
            PasswordResetToken resetToken = PasswordResetToken.builder()
                    .token(rawToken)
                    .user(user)
                    .expiryDate(Instant.now().plus(EXPIRY_HOURS, ChronoUnit.HOURS))
                    .build();
            tokenRepository.save(resetToken);

            emailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), rawToken);
            log.info("PasswordReset: reset token issued for user '{}'", user.getUsername());
        });
    }

    /**
     * Validate the reset token and apply the new password.
     *
     * @throws IllegalArgumentException when the token is unknown, expired, or already used.
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken resetToken = tokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Password reset token is invalid or has already been used"));

        if (resetToken.isUsed()) {
            throw new IllegalArgumentException("Password reset token is invalid or has already been used");
        }
        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Password reset token has expired — please request a new one");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(java.time.LocalDateTime.now());
        userRepository.save(user);

        // Mark token as used — prevents replay attacks
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        // Revoke all refresh tokens so stale sessions are immediately invalidated
        refreshTokenService.deleteByUsername(user.getUsername());

        log.info("PasswordReset: password successfully reset for user '{}'", user.getUsername());
    }

    /** Hourly cleanup — remove expired and used reset tokens from the DB. */
    @Scheduled(fixedDelayString = "${security.attempt-cleanup-interval-ms:3600000}")
    @Transactional
    public void cleanupExpiredTokens() {
        tokenRepository.deleteExpiredOrUsed(Instant.now());
        log.debug("PasswordReset: cleaned up expired/used reset tokens");
    }
}
