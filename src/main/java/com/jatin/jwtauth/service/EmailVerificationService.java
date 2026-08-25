package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * EmailVerificationService — manages the verification token lifecycle.
 *
 * Key learning points:
 *  1. Tokens are opaque UUIDs — not JWTs — because they are single-use
 *     and must be revocable (cleared from DB after use).
 *  2. generateAndSendToken() is called from AuthService.register() after
 *     the user is saved. If the user has no email, verification is skipped.
 *  3. verifyToken() finds the user by token, marks emailVerified=true,
 *     clears the token so it cannot be reused, and saves.
 *  4. resendVerification() replaces any existing token with a fresh UUID
 *     and re-sends the email — safe to call repeatedly.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    /**
     * Generate a fresh verification token for the user and send the email.
     * No-op if the user has no email address or is already verified.
     */
    @Transactional
    public void generateAndSendToken(String username) {
        User user = findUser(username);

        if (user.getEmail() == null || user.isEmailVerified()) {
            return; // nothing to do
        }

        String token = UUID.randomUUID().toString();
        user.setVerificationToken(token);
        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), username, token);
    }

    /**
     * Verify a token from the email link.
     *
     * @throws IllegalArgumentException if the token is unknown or already used.
     */
    @Transactional
    public void verifyToken(String token) {
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Verification token is invalid or has already been used"));

        user.setEmailVerified(true);
        user.setVerificationToken(null);   // single-use — clear after verification
        userRepository.save(user);
        log.info("EmailVerification: user '{}' verified their email", user.getUsername());
    }

    /**
     * Replace the existing token with a new one and re-send the email.
     * Called from POST /api/auth/resend-verification.
     *
     * @throws IllegalArgumentException if user has no email or is already verified.
     */
    @Transactional
    public void resendVerification(String username) {
        User user = findUser(username);

        if (user.getEmail() == null) {
            throw new IllegalArgumentException(
                    "No email address on file — update your profile first");
        }
        if (user.isEmailVerified()) {
            throw new IllegalArgumentException("Email is already verified");
        }

        String token = UUID.randomUUID().toString();
        user.setVerificationToken(token);
        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), username, token);
        log.info("EmailVerification: resent verification email to user '{}'", username);
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
}
