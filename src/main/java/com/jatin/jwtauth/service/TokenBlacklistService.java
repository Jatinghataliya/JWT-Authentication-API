package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.BlacklistedToken;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * TokenBlacklistService — manages the lifecycle of revoked access-token JTIs.
 *
 * Key learning points:
 *  1. blacklist(jti, expiresAt) is called on logout to immediately invalidate
 *     the access token even before it naturally expires.
 *  2. isBlacklisted(jti) is called by JwtAuthFilter on every request — one DB
 *     read (index hit on jti column) per authenticated request.
 *  3. The @Scheduled cleanup runs every hour to prune expired rows, keeping
 *     the table small and the existsByJti check fast.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    /**
     * Adds the given JTI to the blacklist.
     * Called when a user explicitly logs out.
     *
     * @param jti       the JWT ID claim of the access token being revoked
     * @param expiresAt the token's natural expiry (mirrors the "exp" JWT claim)
     */
    @Transactional
    public void blacklist(String jti, Instant expiresAt) {
        if (!blacklistedTokenRepository.existsByJti(jti)) {
            blacklistedTokenRepository.save(
                    BlacklistedToken.builder()
                            .jti(jti)
                            .expiresAt(expiresAt)
                            .build()
            );
            log.debug("TokenBlacklist: revoked JTI={}", jti);
        }
    }

    /**
     * Returns true if the given JTI has been explicitly revoked.
     * Called on every authenticated request in JwtAuthFilter.
     */
    public boolean isBlacklisted(String jti) {
        return blacklistedTokenRepository.existsByJti(jti);
    }

    /**
     * Scheduled cleanup — removes expired blacklist entries every hour.
     * Safe to call repeatedly; expired tokens would be rejected by the JWT
     * parser anyway, so these rows are redundant once past their expiry.
     */
    @Scheduled(fixedRateString = "${jwt.blacklist.cleanup-interval-ms:3600000}")
    @Transactional
    public void purgeExpiredTokens() {
        int deleted = blacklistedTokenRepository.deleteAllExpiredBefore(Instant.now());
        if (deleted > 0) {
            log.info("TokenBlacklist: purged {} expired entries", deleted);
        }
    }
}
