package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.repository.AuditEventRepository;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.RateLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 10 — Rate Limiting (Bucket4j).
 *
 * The test application.yml sets capacity=5 so we can exhaust the bucket quickly.
 * RateLimitService.reset() is called in setUp to ensure a fresh bucket per test.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RateLimitIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @Autowired private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private RateLimitService rateLimitService;
    @MockBean  private JavaMailSender javaMailSender;

    @BeforeEach
    void setUp() throws Exception {
        rateLimitService.reset();
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        auditEventRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Register a test user
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))))
                .andExpect(status().isCreated());

        // Reset again after registration (register doesn't go through the rate limiter)
        rateLimitService.reset();
    }

    @Test
    @DisplayName("Login within the rate limit → 200 OK")
    void login_withinLimit_returns200() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Exceeding rate limit on login → 429 Too Many Requests")
    void login_exceedRateLimit_returns429() throws Exception {
        // Exhaust the 5-token bucket (capacity=5 in test config)
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))))
                    .andExpect(status().isOk());
        }

        // 6th request should be rate-limited
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("Rate limit response contains correct JSON error body")
    void login_rateLimited_returnsCorrectBody() throws Exception {
        // Exhaust the bucket
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))));
        }

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))))
                .andExpect(status().is(429))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"));
    }

    @Test
    @DisplayName("Rate limit does NOT apply to /register (interceptor is scoped to /login)")
    void register_notRateLimited_after429Login() throws Exception {
        // Exhaust the login bucket
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authReq("rateuser", "secret123"))));
        }

        // Register still works (different path, no interceptor)
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("anotheruser", "secret123"))))
                .andExpect(status().isCreated());
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private AuthRequest authReq(String username, String password) {
        AuthRequest r = new AuthRequest();
        r.setUsername(username);
        r.setPassword(password);
        return r;
    }
}
