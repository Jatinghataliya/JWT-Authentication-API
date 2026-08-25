package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.UpdateProfileRequest;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 6 — Email Verification on Registration.
 *
 * JavaMailSender is mocked with @MockBean so no real SMTP server is needed.
 * The verification token is read directly from the DB for end-to-end testing.
 */
@SpringBootTest
@AutoConfigureMockMvc
class EmailVerificationIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;

    /** Mock the mail sender — no real SMTP needed in tests. */
    @MockBean private JavaMailSender javaMailSender;

    private String accessToken;

    @BeforeEach
    void setUp() throws Exception {
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Register a fresh user — email not set yet at registration
        accessToken = registerAndGetToken("jatin", "secret123");
    }

    // ─── GET /api/auth/verify ────────────────────────────────────────────────

    @Test
    @DisplayName("New user has emailVerified=false by default")
    void newUser_emailVerifiedFalse() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.emailVerified").value(false));
    }

    @Test
    @DisplayName("Setting email via profile update + manual token verification → emailVerified=true")
    void setEmail_thenVerify_emailVerifiedTrue() throws Exception {
        // 1. Update profile to add an email
        UpdateProfileRequest profileReq = new UpdateProfileRequest();
        profileReq.setEmail("jatin@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileReq)))
                .andExpect(status().isOk());

        // 2. Resend verification to generate a token
        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        // Verify the mail was "sent"
        verify(javaMailSender, atLeastOnce()).send(any(SimpleMailMessage.class));

        // 3. Read the token from DB (simulates clicking the link)
        String token = userRepository.findByUsername("jatin")
                .orElseThrow().getVerificationToken();
        assertThat(token).isNotNull();

        // 4. Call the verify endpoint with the token
        mockMvc.perform(get("/api/auth/verify")
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully"));

        // 5. Confirm emailVerified=true and token cleared
        var user = userRepository.findByUsername("jatin").orElseThrow();
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(user.getVerificationToken()).isNull();
    }

    @Test
    @DisplayName("GET /verify: invalid token → 400 Bad Request")
    void verify_invalidToken_returns400() throws Exception {
        mockMvc.perform(get("/api/auth/verify")
                        .param("token", "00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("invalid or has already been used")));
    }

    @Test
    @DisplayName("GET /verify: token is single-use — second call returns 400")
    void verify_singleUse_secondCallReturns400() throws Exception {
        // Setup email + token
        UpdateProfileRequest profileReq = new UpdateProfileRequest();
        profileReq.setEmail("jatin@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileReq)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        String token = userRepository.findByUsername("jatin").orElseThrow().getVerificationToken();

        // First use — succeeds
        mockMvc.perform(get("/api/auth/verify").param("token", token))
                .andExpect(status().isOk());

        // Second use — token already cleared
        mockMvc.perform(get("/api/auth/verify").param("token", token))
                .andExpect(status().isBadRequest());
    }

    // ─── POST /api/auth/resend-verification ─────────────────────────────────

    @Test
    @DisplayName("Resend: no email on file → 400 Bad Request")
    void resend_noEmail_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("No email address on file")));
    }

    @Test
    @DisplayName("Resend: already verified → 400 Bad Request")
    void resend_alreadyVerified_returns400() throws Exception {
        // Add email + verify
        UpdateProfileRequest profileReq = new UpdateProfileRequest();
        profileReq.setEmail("jatin@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileReq)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        String token = userRepository.findByUsername("jatin").orElseThrow().getVerificationToken();
        mockMvc.perform(get("/api/auth/verify").param("token", token))
                .andExpect(status().isOk());

        // Now resend should fail — already verified
        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("already verified")));
    }

    @Test
    @DisplayName("Resend: no token → 401 Unauthorized")
    void resend_noToken_returns401() throws Exception {
        mockMvc.perform(post("/api/auth/resend-verification"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Resend: sends email and overwrites previous token")
    void resend_replacesTokenAndSendsEmail() throws Exception {
        // Add email
        UpdateProfileRequest profileReq = new UpdateProfileRequest();
        profileReq.setEmail("jatin@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileReq)))
                .andExpect(status().isOk());

        // First resend
        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());
        String firstToken = userRepository.findByUsername("jatin").orElseThrow().getVerificationToken();

        // Second resend — should replace the token
        mockMvc.perform(post("/api/auth/resend-verification")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());
        String secondToken = userRepository.findByUsername("jatin").orElseThrow().getVerificationToken();

        assertThat(secondToken).isNotEqualTo(firstToken);
        verify(javaMailSender, times(2)).send(any(SimpleMailMessage.class));
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
