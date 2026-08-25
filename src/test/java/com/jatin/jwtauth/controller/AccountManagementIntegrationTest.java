package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 4 — Account Management (enable/disable/lock/unlock).
 *
 * Setup: an ADMIN user is seeded directly (no API) and a regular USER is registered
 * via the API so we always have an access token and a known user ID to operate on.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccountManagementIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @MockBean  private JavaMailSender javaMailSender;

    private String adminToken;
    private Long targetUserId;

    @BeforeEach
    void setUp() throws Exception {
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Seed admin directly
        seedUserWithRoles("admin1", "adminpass", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "adminpass");

        // Register a regular user via API — captures their DB id
        registerAndGetToken("target", "pass123");
        targetUserId = userRepository.findByUsername("target").orElseThrow().getId();
    }

    // ─── Disable / Enable ────────────────────────────────────────────────────

    @Test
    @DisplayName("PATCH /disable: admin disables user → enabled=false in response")
    void disableUser_setsEnabledFalse() throws Exception {
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.username").value("target"));
    }

    @Test
    @DisplayName("PATCH /disable then login → 401 Account is disabled")
    void disableUser_thenLogin_returns401Disabled() throws Exception {
        // Disable
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Login should be rejected
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("target", "pass123"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("disabled")));
    }

    @Test
    @DisplayName("PATCH /disable then /enable → login succeeds again")
    void disableUser_thenEnable_loginSucceeds() throws Exception {
        // Disable
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Re-enable
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/enable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));

        // Login should work now
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("target", "pass123"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    // ─── Lock / Unlock ───────────────────────────────────────────────────────

    @Test
    @DisplayName("PATCH /lock: admin locks user → accountNonLocked=false, lockedAt set")
    void lockUser_setsLockedFields() throws Exception {
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/lock")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountNonLocked").value(false))
                .andExpect(jsonPath("$.lockedAt").isNotEmpty())
                .andExpect(jsonPath("$.username").value("target"));
    }

    @Test
    @DisplayName("PATCH /lock then login → 401 Account is locked")
    void lockUser_thenLogin_returns401Locked() throws Exception {
        // Lock
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/lock")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Login should be rejected
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("target", "pass123"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("locked")));
    }

    @Test
    @DisplayName("PATCH /lock then /unlock → login succeeds, lockedAt cleared")
    void lockUser_thenUnlock_loginSucceeds() throws Exception {
        // Lock
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/lock")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Unlock
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/unlock")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountNonLocked").value(true))
                .andExpect(jsonPath("$.lockedAt").doesNotExist());

        // Login should work now
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("target", "pass123"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    // ─── Auth guard ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("PATCH /disable without token → 401 Unauthorized")
    void disableUser_noToken_returns401() throws Exception {
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PATCH /disable with non-admin token → 403 Forbidden")
    void disableUser_nonAdmin_returns403() throws Exception {
        // Log in as the target user (USER role)
        String userToken = loginAndGetToken("target", "pass123");

        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("PATCH /disable on unknown user → 400 Bad Request")
    void disableUser_unknownId_returns400() throws Exception {
        mockMvc.perform(patch("/api/admin/users/999999/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("not found")));
    }

    // ─── UserSummary fields ───────────────────────────────────────────────────

    @Test
    @DisplayName("GET /users/{id}: newly registered user has enabled=true, accountNonLocked=true")
    void getUser_defaultFlags_trueOnNewUser() throws Exception {
        mockMvc.perform(get("/api/admin/users/" + targetUserId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.accountNonLocked").value(true))
                .andExpect(jsonPath("$.lockedAt").doesNotExist());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private String registerAndGetToken(String username, String password) throws Exception {
        AuthRequest req = buildAuthRequest(username, password);
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();
    }

    private void seedUserWithRoles(String username, String pwd, Set<String> roleNames) {
        Set<Role> roles = new java.util.HashSet<>();
        roleNames.forEach(name -> roleRepository.findByName(name).ifPresent(roles::add));
        userRepository.save(User.builder()
                .username(username)
                .password(passwordEncoder.encode(pwd))
                .roles(roles)
                .build());
    }

    private AuthRequest buildAuthRequest(String username, String password) {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }
}
