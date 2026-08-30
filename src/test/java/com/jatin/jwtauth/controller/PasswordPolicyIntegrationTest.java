package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.config.PasswordPolicyConfig;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.ChangePasswordRequest;
import com.jatin.jwtauth.dto.PasswordPolicyDto;
import com.jatin.jwtauth.repository.AuditEventRepository;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.RateLimitService;
import org.junit.jupiter.api.AfterEach;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class PasswordPolicyIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private RateLimitService rateLimitService;
    @Autowired private PasswordPolicyConfig passwordPolicyConfig;
    @MockBean  private JavaMailSender javaMailSender;

    @BeforeEach
    void setUp() {
        rateLimitService.reset();
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        auditEventRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        resetPolicy();
    }

    @AfterEach
    void tearDown() {
        resetPolicy();
    }

    private void resetPolicy() {
        passwordPolicyConfig.setMinLength(6);
        passwordPolicyConfig.setRequireUppercase(false);
        passwordPolicyConfig.setRequireDigit(false);
        passwordPolicyConfig.setRequireSpecialChar(false);
        passwordPolicyConfig.setExpiryDays(0);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private String registerAndGetToken(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    /** Register a user, grant ADMIN role via repo, return its access token. */
    private String setupAdminUser(String username) throws Exception {
        String token = registerAndGetToken(username, "secret123");
        userRepository.findByUsername(username).ifPresent(u -> {
            roleRepository.findByName("ADMIN").ifPresent(role -> {
                u.getRoles().add(role);
                userRepository.save(u);
            });
        });
        return token;
    }

    // ─── Tests: @PasswordStrength validator ───────────────────────────────────

    @Test
    @DisplayName("Register with password shorter than minLength → 400")
    void register_tooShort_returns400() throws Exception {
        passwordPolicyConfig.setMinLength(8);

        AuthRequest req = new AuthRequest();
        req.setUsername("user1");
        req.setPassword("abc");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Register with no uppercase when required → 400 with message")
    void register_missingUppercase_returns400() throws Exception {
        passwordPolicyConfig.setRequireUppercase(true);

        AuthRequest req = new AuthRequest();
        req.setUsername("user2");
        req.setPassword("alllower1");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("uppercase")));
    }

    @Test
    @DisplayName("Register with no digit when required → 400 with message")
    void register_missingDigit_returns400() throws Exception {
        passwordPolicyConfig.setRequireDigit(true);

        AuthRequest req = new AuthRequest();
        req.setUsername("user3");
        req.setPassword("NoDigitHere!");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("digit")));
    }

    @Test
    @DisplayName("Register with no special char when required → 400 with message")
    void register_missingSpecialChar_returns400() throws Exception {
        passwordPolicyConfig.setRequireSpecialChar(true);

        AuthRequest req = new AuthRequest();
        req.setUsername("user4");
        req.setPassword("NoSpecial1");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("special")));
    }

    @Test
    @DisplayName("Register meeting all complexity rules → 201 Created")
    void register_meetsAllRules_returns201() throws Exception {
        passwordPolicyConfig.setMinLength(8);
        passwordPolicyConfig.setRequireUppercase(true);
        passwordPolicyConfig.setRequireDigit(true);
        passwordPolicyConfig.setRequireSpecialChar(true);

        AuthRequest req = new AuthRequest();
        req.setUsername("stronguser");
        req.setPassword("Str0ng@Pass");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());
    }

    // ─── Tests: Password expiry ────────────────────────────────────────────────

    @Test
    @DisplayName("Expired password → 403 PASSWORD_EXPIRED on protected endpoint")
    void expiredPassword_returns403() throws Exception {
        passwordPolicyConfig.setExpiryDays(1);
        String token = registerAndGetToken("expuser", "secret123");

        // Age the passwordChangedAt 2 days into the past
        userRepository.findByUsername("expuser").ifPresent(u -> {
            u.setPasswordChangedAt(java.time.LocalDateTime.now().minusDays(2));
            userRepository.save(u);
        });

        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content().string(containsString("PASSWORD_EXPIRED")));
    }

    @Test
    @DisplayName("Expired password — PUT /api/user/me/password is still allowed (escape hatch)")
    void expiredPassword_changePasswordStillAllowed() throws Exception {
        passwordPolicyConfig.setExpiryDays(1);
        String token = registerAndGetToken("escapeuser", "secret123");

        userRepository.findByUsername("escapeuser").ifPresent(u -> {
            u.setPasswordChangedAt(java.time.LocalDateTime.now().minusDays(2));
            userRepository.save(u);
        });

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("secret123");
        req.setNewPassword("newSecret99");

        // Must NOT be blocked — change-password path is whitelisted
        mockMvc.perform(put("/api/user/me/password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Fresh password within expiry window → 200 OK")
    void freshPassword_returns200() throws Exception {
        passwordPolicyConfig.setExpiryDays(90);
        String token = registerAndGetToken("freshuser", "secret123");

        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Expiry disabled (0) → never blocks even with ancient passwordChangedAt")
    void expiryDisabled_neverBlocks() throws Exception {
        passwordPolicyConfig.setExpiryDays(0);
        String token = registerAndGetToken("neverexpire", "secret123");

        userRepository.findByUsername("neverexpire").ifPresent(u -> {
            u.setPasswordChangedAt(java.time.LocalDateTime.now().minusDays(9999));
            userRepository.save(u);
        });

        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    // ─── Tests: Admin policy endpoints ────────────────────────────────────────

    @Test
    @DisplayName("GET /api/admin/settings/password-policy → 200 with current defaults")
    void getPolicy_returnsCurrentValues() throws Exception {
        String token = setupAdminUser("policyadmin1");

        mockMvc.perform(get("/api/admin/settings/password-policy")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minLength").value(6))
                .andExpect(jsonPath("$.requireUppercase").value(false))
                .andExpect(jsonPath("$.expiryDays").value(0));
    }

    @Test
    @DisplayName("PUT /api/admin/settings/password-policy → updates in-memory config and returns new values")
    void updatePolicy_updatesConfig() throws Exception {
        String token = setupAdminUser("policyadmin2");

        PasswordPolicyDto dto = PasswordPolicyDto.builder()
                .minLength(10)
                .requireUppercase(true)
                .requireDigit(true)
                .requireSpecialChar(true)
                .expiryDays(60)
                .build();

        mockMvc.perform(put("/api/admin/settings/password-policy")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minLength").value(10))
                .andExpect(jsonPath("$.requireUppercase").value(true))
                .andExpect(jsonPath("$.expiryDays").value(60));

        assertThat(passwordPolicyConfig.getMinLength()).isEqualTo(10);
        assertThat(passwordPolicyConfig.getExpiryDays()).isEqualTo(60);
    }

    @Test
    @DisplayName("PUT /api/admin/settings/password-policy without ADMIN → 403 Forbidden")
    void updatePolicy_withoutAdminRole_returns403() throws Exception {
        String token = registerAndGetToken("regularuser", "secret123");

        PasswordPolicyDto dto = PasswordPolicyDto.builder().minLength(10).build();

        mockMvc.perform(put("/api/admin/settings/password-policy")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isForbidden());
    }
}
