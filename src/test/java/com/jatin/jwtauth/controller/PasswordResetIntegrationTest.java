package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.UpdateProfileRequest;
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
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 7 — Password Reset via Email.
 *
 * JavaMailSender is mocked with @MockBean so no real SMTP server is needed.
 * The reset token is read directly from the DB to simulate clicking the email link.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PasswordResetIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @Autowired private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired private RateLimitService rateLimitService;
    @MockBean  private JavaMailSender javaMailSender;

    private String accessToken;

    @BeforeEach
    void setUp() throws Exception {
        rateLimitService.reset();
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        accessToken = registerAndGetToken("jatin", "secret123");

        // Give the user an email so forgot-password can find them
        UpdateProfileRequest profileReq = new UpdateProfileRequest();
        profileReq.setEmail("jatin@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileReq)))
                .andExpect(status().isOk());
    }

    // ─── POST /api/auth/forgot-password ─────────────────────────────────────

    @Test
    @DisplayName("forgot-password: known email → 204 + email sent")
    void forgotPassword_knownEmail_returns204AndSendsEmail() throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "jatin@example.com"))))
                .andExpect(status().isNoContent());

        verify(javaMailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("forgot-password: unknown email → 204 (no enumeration) + no email sent")
    void forgotPassword_unknownEmail_returns204NoEmail() throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "nobody@example.com"))))
                .andExpect(status().isNoContent());

        verify(javaMailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("forgot-password: invalid email format → 400")
    void forgotPassword_invalidEmail_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "not-an-email"))))
                .andExpect(status().isBadRequest());
    }

    // ─── POST /api/auth/reset-password ──────────────────────────────────────

    @Test
    @DisplayName("reset-password: valid token → 204 + login succeeds with new password")
    void resetPassword_validToken_changesPassword() throws Exception {
        // 1. Request reset
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "jatin@example.com"))))
                .andExpect(status().isNoContent());

        // 2. Read token from DB
        String token = passwordResetTokenRepository.findAll().get(0).getToken();

        // 3. Reset the password
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("token", token, "newPassword", "newSecret456"))))
                .andExpect(status().isNoContent());

        // 4. Login with new password succeeds
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", "jatin", "password", "newSecret456"))))
                .andExpect(status().isOk());

        // 5. Login with old password fails
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", "jatin", "password", "secret123"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("reset-password: invalid token → 400 Bad Request")
    void resetPassword_invalidToken_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("token", "00000000-0000-0000-0000-000000000000", "newPassword", "newSecret456"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("invalid or has already been used")));
    }

    @Test
    @DisplayName("reset-password: token is single-use — second call returns 400")
    void resetPassword_singleUse_secondCallReturns400() throws Exception {
        // Request reset
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "jatin@example.com"))))
                .andExpect(status().isNoContent());

        String token = passwordResetTokenRepository.findAll().get(0).getToken();

        // First reset — succeeds
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("token", token, "newPassword", "newSecret456"))))
                .andExpect(status().isNoContent());

        // Second use — token already used
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("token", token, "newPassword", "anotherPwd789"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("reset-password: short new password → 400 Bad Request")
    void resetPassword_shortPassword_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "jatin@example.com"))))
                .andExpect(status().isNoContent());

        String token = passwordResetTokenRepository.findAll().get(0).getToken();

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("token", token, "newPassword", "abc"))))
                .andExpect(status().isBadRequest());
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private String registerAndGetToken(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();
    }
}
