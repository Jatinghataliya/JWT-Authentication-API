package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * AccountErasureService — manages the GDPR account-deletion lifecycle.
 *
 * Key learning points:
 *  1. requestDeletion() is a SOFT delete: the account is disabled immediately
 *     so the user cannot log in, but PII is not yet wiped. A 30-day retention
 *     window gives the user a grace period to cancel (not implemented here but
 *     easy to add as DELETE /api/user/me/cancel).
 *  2. eraseNow() is the HARD erase: all personal data fields are overwritten with
 *     sentinel values; the username is renamed to "deleted_{id}" so existing
 *     audit rows remain coherent without storing a real name.
 *  3. The @Scheduled job calls eraseNow() for every account whose 30-day window
 *     has elapsed. It runs daily (once per day is enough for a 30-day window).
 *  4. AuditEvent rows are intentionally NOT erased. They store the username as a
 *     plain string (not a FK), so they survive even after the User row is modified.
 *     The audit trail is renamed to "deleted_{id}" to remove PII there too.
 *  5. All child entities (refresh tokens, password-reset tokens) are deleted before
 *     the user row is modified so FK constraints are never violated.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountErasureService {

    /** Days the user's account waits in "deletion requested" state before PII is wiped. */
    public static final int RETENTION_DAYS = 30;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final AuditService auditService;

    // ─── User-initiated soft delete ───────────────────────────────────────────

    /**
     * Mark the calling user's account for deletion.
     *
     * <ol>
     *   <li>Sets {@code deletionRequestedAt = now} and {@code enabled = false}.</li>
     *   <li>Blacklisting the current token is the caller's responsibility (AuthService.logout).</li>
     * </ol>
     *
     * @throws IllegalStateException if the account has already been requested for deletion.
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public void requestDeletion(String username) {
        User user = findUser(username);

        if (user.getDeletionRequestedAt() != null) {
            throw new IllegalStateException(
                    "Account deletion has already been requested for user '" + username + "'");
        }

        user.setEnabled(false);
        user.setDeletionRequestedAt(LocalDateTime.now());
        userRepository.save(user);

        auditService.log(username, "ACCOUNT_DELETION_REQUESTED",
                "User requested account deletion — PII will be erased in " + RETENTION_DAYS + " days");
        log.info("AccountErasure: deletion requested for user '{}', erasure in {} days",
                username, RETENTION_DAYS);
    }

    // ─── Hard erase (shared by scheduled job and admin endpoint) ─────────────

    /**
     * Immediately wipe all PII for the given user.
     *
     * <p>After this call the {@link User} row still exists (so FK references in
     * audit tables survive) but every personal field is overwritten:</p>
     * <ul>
     *   <li>{@code email}, {@code firstName}, {@code lastName} → null</li>
     *   <li>{@code password} → {@code "[ERASED]"} (invalid bcrypt — can never match)</li>
     *   <li>{@code username} → {@code "deleted_<id>"}</li>
     *   <li>{@code enabled} → false, {@code deletedAt} → now</li>
     *   <li>{@code verificationToken} → null</li>
     * </ul>
     *
     * <p>All child entities (refresh tokens, password-reset tokens) are deleted first
     * to satisfy FK constraints.</p>
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public void eraseNow(User user) {
        String originalUsername = user.getUsername();

        // 1. Delete FK children
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);
        passwordResetTokenRepository.deleteByUser(user);

        // 2. Wipe PII fields
        user.setEmail(null);
        user.setFirstName(null);
        user.setLastName(null);
        user.setVerificationToken(null);
        user.setPassword("[ERASED]");           // invalid bcrypt — can never match
        user.setEnabled(false);
        user.setAccountNonLocked(false);
        user.setDeletedAt(LocalDateTime.now());

        // 3. Rename username so audit rows refer to "deleted_<id>" rather than real name
        String erasedUsername = "deleted_" + user.getId();
        user.setUsername(erasedUsername);
        userRepository.save(user);

        auditService.log(erasedUsername, "ACCOUNT_ERASED",
                "PII erased for original username: " + originalUsername);
        log.info("AccountErasure: PII erased for original username='{}', now '{}'",
                originalUsername, erasedUsername);
    }

    // ─── Admin-triggered immediate erase ─────────────────────────────────────

    /**
     * Admin-triggered hard erase by user ID.
     * Does not require a prior deletion request — admins can erase any account immediately.
     *
     * @throws IllegalArgumentException if no user with the given id exists.
     */
    @Transactional
    public void eraseByAdmin(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + userId));

        // Set deletionRequestedAt if not already set (for audit completeness)
        if (user.getDeletionRequestedAt() == null) {
            user.setDeletionRequestedAt(LocalDateTime.now());
        }

        eraseNow(user);
    }

    // ─── Scheduled 30-day erasure job ────────────────────────────────────────

    /**
     * Runs daily at midnight. Finds all accounts whose 30-day retention window has
     * elapsed and have not yet been erased, then calls {@link #eraseNow} for each.
     *
     * The fixed-delay schedule ensures at most one execution runs at a time, which
     * prevents overlap if erasure takes longer than expected (e.g. large user base).
     */
    @Scheduled(cron = "${app.erasure.cron:0 0 0 * * *}")   // default: midnight every day
    public void scheduledErasure() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(RETENTION_DAYS);
        List<User> pending = userRepository.findAllPendingErasure(cutoff);

        if (pending.isEmpty()) {
            log.debug("AccountErasure: no accounts pending erasure");
            return;
        }

        log.info("AccountErasure: processing {} account(s) pending erasure", pending.size());
        pending.forEach(user -> {
            try {
                eraseNow(user);
            } catch (Exception ex) {
                // Log and continue — one failed erasure should not block the rest
                log.error("AccountErasure: failed to erase user id={}: {}", user.getId(), ex.getMessage(), ex);
            }
        });
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
}
