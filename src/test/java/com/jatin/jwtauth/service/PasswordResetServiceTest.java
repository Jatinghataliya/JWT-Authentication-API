package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.PasswordResetToken;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PasswordResetService — covers token validation edge cases
 * (expired, used, unknown) and verifies refresh-token revocation on success.
 */
@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordResetTokenRepository tokenRepository;
    @Mock private EmailService emailService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private RefreshTokenService refreshTokenService;

    @InjectMocks
    private PasswordResetService passwordResetService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .username("jatin")
                .email("jatin@example.com")
                .password("$2a$10$encoded")
                .build();
    }

    // ─── resetPassword — happy path ──────────────────────────────────────────

    @Test
    @DisplayName("resetPassword: valid unused, non-expired token → password changed, token marked used, refresh tokens revoked")
    void resetPassword_validToken_changesPasswordAndRevokesRefreshTokens() {
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token("valid-uuid")
                .user(testUser)
                .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                .used(false)
                .build();

        when(tokenRepository.findByToken("valid-uuid")).thenReturn(Optional.of(resetToken));
        when(passwordEncoder.encode("newPass123")).thenReturn("$2a$10$newEncoded");

        passwordResetService.resetPassword("valid-uuid", "newPass123");

        // Password is encoded and saved
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getPassword()).isEqualTo("$2a$10$newEncoded");

        // Token is marked as used
        assertThat(resetToken.isUsed()).isTrue();
        verify(tokenRepository).save(resetToken);

        // Refresh tokens are revoked so stale sessions are invalidated
        verify(refreshTokenService).deleteByUsername("jatin");
    }

    // ─── resetPassword — expired token ──────────────────────────────────────

    @Test
    @DisplayName("resetPassword: expired token → throws IllegalArgumentException with 'expired' message")
    void resetPassword_expiredToken_throwsException() {
        PasswordResetToken expiredToken = PasswordResetToken.builder()
                .token("expired-uuid")
                .user(testUser)
                .expiryDate(Instant.now().minus(2, ChronoUnit.HOURS))  // 2 hours in the past
                .used(false)
                .build();

        when(tokenRepository.findByToken("expired-uuid")).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> passwordResetService.resetPassword("expired-uuid", "newPass123"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");

        // Password must NOT be changed
        verify(userRepository, never()).save(any());
        verify(refreshTokenService, never()).deleteByUsername(anyString());
    }

    // ─── resetPassword — already-used token ──────────────────────────────────

    @Test
    @DisplayName("resetPassword: already-used token → throws IllegalArgumentException")
    void resetPassword_alreadyUsedToken_throwsException() {
        PasswordResetToken usedToken = PasswordResetToken.builder()
                .token("used-uuid")
                .user(testUser)
                .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                .used(true)  // already consumed
                .build();

        when(tokenRepository.findByToken("used-uuid")).thenReturn(Optional.of(usedToken));

        assertThatThrownBy(() -> passwordResetService.resetPassword("used-uuid", "newPass123"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid or has already been used");

        verify(userRepository, never()).save(any());
    }

    // ─── resetPassword — unknown token ───────────────────────────────────────

    @Test
    @DisplayName("resetPassword: unknown token → throws IllegalArgumentException")
    void resetPassword_unknownToken_throwsException() {
        when(tokenRepository.findByToken("no-such-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> passwordResetService.resetPassword("no-such-token", "newPass123"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid or has already been used");

        verify(userRepository, never()).save(any());
    }

    // ─── requestReset — known email ──────────────────────────────────────────

    @Test
    @DisplayName("requestReset: known email → existing tokens deleted, new token saved, email sent")
    void requestReset_knownEmail_deletesOldTokenSavesNewAndSendsEmail() {
        when(userRepository.findByEmail("jatin@example.com")).thenReturn(Optional.of(testUser));

        passwordResetService.requestReset("jatin@example.com");

        // Old tokens for this user are deleted first
        verify(tokenRepository).deleteByUser(testUser);

        // A new token is saved
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        PasswordResetToken saved = tokenCaptor.getValue();
        assertThat(saved.getToken()).isNotNull().isNotBlank();
        assertThat(saved.getUser()).isEqualTo(testUser);
        assertThat(saved.isUsed()).isFalse();
        assertThat(saved.getExpiryDate()).isAfter(Instant.now());

        // Email is dispatched with the raw token
        verify(emailService).sendPasswordResetEmail(
                eq("jatin@example.com"), eq("jatin"), eq(saved.getToken()));
    }
}
