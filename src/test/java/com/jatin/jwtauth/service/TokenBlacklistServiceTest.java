package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.BlacklistedToken;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TokenBlacklistService — verifies that JTIs are persisted,
 * duplicates are ignored, lookup delegates to the repository, and the
 * scheduled purge calls the correct delete query.
 */
@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock private BlacklistedTokenRepository blacklistedTokenRepository;

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    // ─── blacklist() ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("blacklist: new JTI → saved to repository with correct fields")
    void blacklist_newJti_savesRecord() {
        String jti = "jti-abc-123";
        Instant expiresAt = Instant.now().plus(15, ChronoUnit.MINUTES);

        when(blacklistedTokenRepository.existsByJti(jti)).thenReturn(false);

        tokenBlacklistService.blacklist(jti, expiresAt);

        ArgumentCaptor<BlacklistedToken> captor = ArgumentCaptor.forClass(BlacklistedToken.class);
        verify(blacklistedTokenRepository).save(captor.capture());

        BlacklistedToken saved = captor.getValue();
        assertThat(saved.getJti()).isEqualTo(jti);
        assertThat(saved.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    @DisplayName("blacklist: duplicate JTI → save is NOT called again (idempotent)")
    void blacklist_duplicateJti_isIdempotent() {
        String jti = "jti-already-blacklisted";

        when(blacklistedTokenRepository.existsByJti(jti)).thenReturn(true);

        tokenBlacklistService.blacklist(jti, Instant.now().plus(15, ChronoUnit.MINUTES));

        verify(blacklistedTokenRepository, never()).save(any());
    }

    // ─── isBlacklisted() ─────────────────────────────────────────────────────

    @Test
    @DisplayName("isBlacklisted: JTI is in blacklist → returns true")
    void isBlacklisted_knownJti_returnsTrue() {
        when(blacklistedTokenRepository.existsByJti("revoked-jti")).thenReturn(true);

        assertThat(tokenBlacklistService.isBlacklisted("revoked-jti")).isTrue();
    }

    @Test
    @DisplayName("isBlacklisted: JTI not in blacklist → returns false")
    void isBlacklisted_unknownJti_returnsFalse() {
        when(blacklistedTokenRepository.existsByJti("clean-jti")).thenReturn(false);

        assertThat(tokenBlacklistService.isBlacklisted("clean-jti")).isFalse();
    }

    // ─── purgeExpiredTokens() ────────────────────────────────────────────────

    @Test
    @DisplayName("purgeExpiredTokens: delegates to deleteAllExpiredBefore with current time")
    void purgeExpiredTokens_callsRepositoryDelete() {
        when(blacklistedTokenRepository.deleteAllExpiredBefore(any(Instant.class))).thenReturn(3);

        tokenBlacklistService.purgeExpiredTokens();

        // deleteAllExpiredBefore must be called with a timestamp at or before now
        ArgumentCaptor<Instant> captor = ArgumentCaptor.forClass(Instant.class);
        verify(blacklistedTokenRepository).deleteAllExpiredBefore(captor.capture());
        assertThat(captor.getValue()).isBeforeOrEqualTo(Instant.now());
    }
}
