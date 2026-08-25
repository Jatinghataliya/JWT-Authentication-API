package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.RefreshToken;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RefreshTokenService — verifies token creation, expiry detection,
 * unknown-token handling, and deletion by username.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .username("jatin")
                .password("$2a$10$encoded")
                .build();
    }

    // ─── createRefreshToken ──────────────────────────────────────────────────

    @Test
    @DisplayName("createRefreshToken: no prior token exists → saves and returns new token with future expiry")
    void createRefreshToken_noPriorToken_returnsNewToken() {
        when(userRepository.findByUsername("jatin")).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.findByUser(testUser)).thenReturn(Optional.empty());

        RefreshToken newToken = RefreshToken.builder()
                .id(1L)
                .token("fresh-uuid")
                .user(testUser)
                .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))
                .build();
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(newToken);

        RefreshToken result = refreshTokenService.createRefreshToken("jatin");

        assertThat(result.getToken()).isEqualTo("fresh-uuid");
        assertThat(result.getExpiryDate()).isAfter(Instant.now());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("createRefreshToken: prior token exists → old token deleted before new one is created")
    void createRefreshToken_priorTokenExists_deletesOldFirst() {
        RefreshToken oldToken = RefreshToken.builder()
                .id(99L)
                .token("old-uuid")
                .user(testUser)
                .expiryDate(Instant.now().plus(1, ChronoUnit.DAYS))
                .build();

        when(userRepository.findByUsername("jatin")).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.findByUser(testUser)).thenReturn(Optional.of(oldToken));

        RefreshToken newToken = RefreshToken.builder()
                .id(100L)
                .token("new-uuid")
                .user(testUser)
                .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))
                .build();
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(newToken);

        refreshTokenService.createRefreshToken("jatin");

        verify(refreshTokenRepository).delete(oldToken);
        verify(refreshTokenRepository).flush();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    // ─── verifyExpiration ────────────────────────────────────────────────────

    @Test
    @DisplayName("verifyExpiration: expired token → deleted from DB and throws IllegalArgumentException")
    void verifyExpiration_expiredToken_deletesAndThrows() {
        RefreshToken expiredToken = RefreshToken.builder()
                .token("expired-uuid")
                .user(testUser)
                .expiryDate(Instant.now().minus(1, ChronoUnit.HOURS))  // already past
                .build();

        when(refreshTokenRepository.findByToken("expired-uuid")).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> refreshTokenService.verifyExpiration("expired-uuid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");

        // Expired token must be cleaned up immediately
        verify(refreshTokenRepository).delete(expiredToken);
    }

    @Test
    @DisplayName("verifyExpiration: unknown token → throws IllegalArgumentException without DB delete")
    void verifyExpiration_unknownToken_throwsWithoutDelete() {
        when(refreshTokenRepository.findByToken("no-such-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.verifyExpiration("no-such-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not found");

        verify(refreshTokenRepository, never()).delete(any(RefreshToken.class));
    }
}
