package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.LoginAttemptSummary;
import com.jatin.jwtauth.entity.LoginAttempt;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for LoginAttemptService — verifies attempt recording, the
 * brute-force auto-lock trigger, and the admin query helper.
 */
@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    @Mock private LoginAttemptRepository loginAttemptRepository;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private LoginAttemptService loginAttemptService;

    private User lockedCandidate;

    @BeforeEach
    void setUp() {
        // Mirror the test application.yml value (max-failed-attempts: 3)
        ReflectionTestUtils.setField(loginAttemptService, "maxFailedAttempts", 3);
        ReflectionTestUtils.setField(loginAttemptService, "lockoutDurationMinutes", 30);

        lockedCandidate = User.builder()
                .id(1L)
                .username("jatin")
                .accountNonLocked(true)
                .build();
    }

    // ─── recordSuccess ───────────────────────────────────────────────────────

    @Test
    @DisplayName("recordSuccess: persists a success=true LoginAttempt row")
    void recordSuccess_savesSuccessRow() {
        loginAttemptService.recordSuccess("jatin", "127.0.0.1");

        ArgumentCaptor<LoginAttempt> captor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository).save(captor.capture());

        LoginAttempt saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo("jatin");
        assertThat(saved.isSuccess()).isTrue();
        assertThat(saved.getIpAddress()).isEqualTo("127.0.0.1");
    }

    // ─── recordFailure — below threshold ────────────────────────────────────

    @Test
    @DisplayName("recordFailure: failure count below threshold → account NOT locked")
    void recordFailure_belowThreshold_doesNotLockAccount() {
        // Only 2 failures — threshold is 3
        when(loginAttemptRepository.countFailedSince(eq("jatin"), any(LocalDateTime.class)))
                .thenReturn(2);

        loginAttemptService.recordFailure("jatin", "127.0.0.1");

        // A failure row is persisted
        verify(loginAttemptRepository).save(any(LoginAttempt.class));
        // But account lock is never triggered
        verify(userRepository, never()).findByUsername(anyString());
    }

    // ─── recordFailure — at threshold ────────────────────────────────────────

    @Test
    @DisplayName("recordFailure: failure count reaches threshold → account is auto-locked")
    void recordFailure_atThreshold_locksAccount() {
        when(loginAttemptRepository.countFailedSince(eq("jatin"), any(LocalDateTime.class)))
                .thenReturn(3);  // exactly at maxFailedAttempts
        when(userRepository.findByUsername("jatin")).thenReturn(Optional.of(lockedCandidate));

        loginAttemptService.recordFailure("jatin", "10.0.0.1");

        // The account is locked
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().isAccountNonLocked()).isFalse();
        assertThat(userCaptor.getValue().getLockedAt()).isNotNull();
    }

    // ─── getRecentAttempts ───────────────────────────────────────────────────

    @Test
    @DisplayName("getRecentAttempts: returns mapped LoginAttemptSummary list from repository")
    void getRecentAttempts_returnsMappedSummaries() {
        LoginAttempt attempt = LoginAttempt.builder()
                .id(1L)
                .username("jatin")
                .ipAddress("192.168.1.1")
                .success(false)
                .attemptedAt(LocalDateTime.now())
                .build();

        when(loginAttemptRepository.findTop20ByUsernameOrderByAttemptedAtDesc("jatin"))
                .thenReturn(List.of(attempt));

        List<LoginAttemptSummary> result = loginAttemptService.getRecentAttempts("jatin");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getUsername()).isEqualTo("jatin");
        assertThat(result.get(0).isSuccess()).isFalse();
    }
}
