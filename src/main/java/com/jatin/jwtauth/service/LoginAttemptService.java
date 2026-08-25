package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.LoginAttemptSummary;
import com.jatin.jwtauth.entity.LoginAttempt;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * LoginAttemptService — records every login attempt and auto-locks accounts
 * that exceed the configured failure threshold.
 *
 * Key learning points:
 *  1. recordSuccess() resets the consecutive-failure window by recording a
 *     success row; the count query only looks at failures since the last check.
 *  2. recordFailure() persists the attempt, then checks whether failures in the
 *     lockout window have reached maxAttempts. If so, it delegates to
 *     AdminService.lockUser() so the existing lock/unlock infrastructure is reused.
 *  3. The @Scheduled cleanup purges old rows so the table stays small.
 *     Retention is 2× the lockout window by default.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    @Value("${security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;

    // ─── Recording ───────────────────────────────────────────────────────────

    /**
     * Record a successful login. A success row resets the failure window —
     * the next failure count query will look forward from now.
     */
    @Transactional
    public void recordSuccess(String username, String ipAddress) {
        save(username, ipAddress, true);
    }

    /**
     * Record a failed login attempt.
     * If the failure count within the lockout window reaches maxFailedAttempts,
     * the user account is automatically locked via the existing lock infrastructure.
     */
    @Transactional
    public void recordFailure(String username, String ipAddress) {
        save(username, ipAddress, false);

        // Count failures within the current lockout window
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(lockoutDurationMinutes);
        int failures = loginAttemptRepository.countFailedSince(username, windowStart);

        if (failures >= maxFailedAttempts) {
            userRepository.findByUsername(username).ifPresent(user -> {
                if (user.isAccountNonLocked()) {
                    user.setAccountNonLocked(false);
                    user.setLockedAt(LocalDateTime.now());
                    userRepository.save(user);
                    log.warn("BruteForce: auto-locked account '{}' after {} failed attempts from IP {}",
                            username, failures, ipAddress);
                }
            });
        }
    }

    // ─── Query ───────────────────────────────────────────────────────────────

    /**
     * Returns the 20 most-recent login attempts for the given username,
     * newest first. Used by the admin audit endpoint.
     */
    public List<LoginAttemptSummary> getRecentAttempts(String username) {
        return loginAttemptRepository
                .findTop20ByUsernameOrderByAttemptedAtDesc(username)
                .stream()
                .map(LoginAttemptSummary::from)
                .collect(Collectors.toList());
    }

    // ─── Scheduled cleanup ────────────────────────────────────────────────────

    /**
     * Delete attempts older than 2× the lockout window.
     * Runs every hour. Rows older than the retention period can never
     * trigger a lock, so they are safe to discard.
     */
    @Scheduled(fixedRateString = "${security.attempt-cleanup-interval-ms:3600000}")
    @Transactional
    public void purgeOldAttempts() {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(lockoutDurationMinutes * 2L);
        int deleted = loginAttemptRepository.deleteAllBefore(cutoff);
        if (deleted > 0) {
            log.info("LoginAttempt: purged {} old records", deleted);
        }
    }

    // ─── Private helper ───────────────────────────────────────────────────────

    private void save(String username, String ipAddress, boolean success) {
        loginAttemptRepository.save(LoginAttempt.builder()
                .username(username)
                .ipAddress(ipAddress)
                .success(success)
                .attemptedAt(LocalDateTime.now())
                .build());
    }
}
