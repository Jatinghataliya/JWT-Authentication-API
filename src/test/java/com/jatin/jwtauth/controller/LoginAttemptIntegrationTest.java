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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 5 — Login Attempt Tracking & Brute-Force Protection.
 *
 * The test application.yml sets max-failed-attempts=3 so tests don't need 5 tries.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginAttemptIntegrationTest {

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
        blacklistedTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        loginAttemptRepository.deleteAll();
        userRepository.deleteAll();

        seedUserWithRoles("admin1", "adminpass", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "adminpass");

        // Register a target user
        registerUser("victim", "correctpass");
        targetUserId = userRepository.findByUsername("victim").orElseThrow().getId();
    }

    // ─── Attempt recording ───────────────────────────────────────────────────

    @Test
    @DisplayName("Successful login is recorded in login_attempts")
    void successfulLogin_recorded() throws Exception {
        loginAndGetToken("victim", "correctpass");

        assertThat(loginAttemptRepository.findTop20ByUsernameOrderByAttemptedAtDesc("victim"))
                .isNotEmpty()
                .allMatch(a -> a.isSuccess());
    }

    @Test
    @DisplayName("Failed login is recorded with success=false")
    void failedLogin_recorded() throws Exception {
        attemptLogin("victim", "wrongpass");

        assertThat(loginAttemptRepository.findTop20ByUsernameOrderByAttemptedAtDesc("victim"))
                .hasSize(1)
                .allMatch(a -> !a.isSuccess());
    }

    // ─── Auto-lock ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("3 consecutive failures auto-lock the account → 4th attempt returns 401 locked")
    void threeFailures_autoLock_fourthReturnsLocked() throws Exception {
        // 3 wrong-password attempts (threshold = 3 in test config)
        // password must be ≥6 chars to pass validation and reach AuthService
        for (int i = 0; i < 3; i++) {
            attemptLogin("victim", "wrongpassword");
        }

        // Account should now be locked in the DB
        User user = userRepository.findByUsername("victim").orElseThrow();
        assertThat(user.isAccountNonLocked()).isFalse();
        assertThat(user.getLockedAt()).isNotNull();

        // 4th attempt (correct password!) should fail with locked message
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("victim", "correctpass"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("locked")));
    }

    @Test
    @DisplayName("After auto-lock, admin unlock + successful login resets failure window")
    void afterAutoLock_adminUnlock_loginSucceeds() throws Exception {
        // Auto-lock
        for (int i = 0; i < 3; i++) {
            attemptLogin("victim", "wrongpassword");
        }

        // Admin unlocks
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/unlock")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountNonLocked").value(true));

        // Login with correct password should succeed
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("victim", "correctpass"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    @DisplayName("Successful login after 2 failures does NOT lock the account")
    void twoFailuresThenSuccess_doesNotLock() throws Exception {
        // 2 failures (below threshold of 3)
        attemptLogin("victim", "wrongpassword");
        attemptLogin("victim", "wrongpassword");

        // Correct login
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("victim", "correctpass"))))
                .andExpect(status().isOk());

        // Account must still be unlocked
        User user = userRepository.findByUsername("victim").orElseThrow();
        assertThat(user.isAccountNonLocked()).isTrue();
    }

    // ─── Admin audit endpoint ────────────────────────────────────────────────

    @Test
    @DisplayName("GET /admin/users/{id}/login-attempts returns attempt records")
    void getLoginAttempts_returnsRecords() throws Exception {
        loginAndGetToken("victim", "correctpass");
        attemptLogin("victim", "wrongpassword");
        attemptLogin("victim", "wrongpassword");

        mockMvc.perform(get("/api/admin/users/" + targetUserId + "/login-attempts")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)))          // 1 success + 2 failures
                .andExpect(jsonPath("$[0].username").value("victim"))
                .andExpect(jsonPath("$[0].attemptedAt").isNotEmpty());
    }

    @Test
    @DisplayName("GET /admin/users/{id}/login-attempts without token → 401")
    void getLoginAttempts_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/users/" + targetUserId + "/login-attempts"))
                .andExpect(status().isUnauthorized());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private void attemptLogin(String username, String password) throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(buildAuthRequest(username, password))));
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

    private void registerUser(String username, String password) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest(username, password))))
                .andExpect(status().isCreated());
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
