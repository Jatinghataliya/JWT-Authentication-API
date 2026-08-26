package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.AuditEventRepository;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.PasswordResetTokenRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.AccountErasureService;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 20 — GDPR Account Deletion & Erasure.
 *
 * Covers:
 *  - User-initiated soft delete (DELETE /api/user/me)
 *  - Second request returns 409 Conflict
 *  - Deleted user cannot log in
 *  - Admin immediate hard-erase (DELETE /api/admin/users/{id}/erase)
 *  - Hard-erase wipes PII fields in DB
 *  - Audit events are recorded for both operations
 *  - Unauthenticated delete request returns 401
 *  - Scheduled erasure job erases accounts past the retention window
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccountErasureIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @Autowired private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private RateLimitService rateLimitService;
    @Autowired private AccountErasureService accountErasureService;
    @MockBean  private JavaMailSender javaMailSender;

    private String userToken;
    private String adminToken;
    private Long targetUserId;

    @BeforeEach
    void setUp() throws Exception {
        rateLimitService.reset();
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        auditEventRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Seed admin directly (bypasses the API to guarantee ADMIN role)
        seedUserWithRoles("admin1", "adminpass", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "adminpass");

        // Register target user via API and capture their DB id
        userToken = registerAndGetToken("jatin", "secret123");
        targetUserId = userRepository.findByUsername("jatin").orElseThrow().getId();
    }

    // ─── DELETE /api/user/me (soft delete) ───────────────────────────────────

    @Test
    @DisplayName("DELETE /api/user/me: authenticated → 204 + account disabled + deletionRequestedAt set")
    void requestDeletion_authenticated_returns204AndDisablesAccount() throws Exception {
        mockMvc.perform(delete("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNoContent());

        User user = userRepository.findByUsername("jatin").orElseThrow();
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getDeletionRequestedAt()).isNotNull();
        assertThat(user.getDeletedAt()).isNull();     // PII not yet erased — within 30-day window
    }

    @Test
    @DisplayName("DELETE /api/user/me: second call → 409 Conflict")
    void requestDeletion_secondCall_returns409() throws Exception {
        // First request — succeeds
        mockMvc.perform(delete("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNoContent());

        // Must get a new token because the user account is now disabled.
        // We re-enable it briefly via admin so we can make the second authenticated call.
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/enable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        String secondToken = loginAndGetToken("jatin", "secret123");

        // Second deletion request
        mockMvc.perform(delete("/api/user/me")
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(containsString("already been requested")));
    }

    @Test
    @DisplayName("DELETE /api/user/me: unauthenticated → 401")
    void requestDeletion_noToken_returns401() throws Exception {
        mockMvc.perform(delete("/api/user/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DELETE /api/user/me: disabled account cannot log in after deletion request")
    void requestDeletion_accountDisabled_loginRejected() throws Exception {
        mockMvc.perform(delete("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNoContent());

        // Login must fail with 401 (account disabled)
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("jatin", "secret123"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("disabled")));
    }

    @Test
    @DisplayName("DELETE /api/user/me: audit event ACCOUNT_DELETION_REQUESTED is recorded")
    void requestDeletion_auditEventRecorded() throws Exception {
        mockMvc.perform(delete("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNoContent());

        boolean found = auditEventRepository.findAll().stream()
                .anyMatch(e -> e.getUsername().equals("jatin")
                        && e.getEventType().equals("ACCOUNT_DELETION_REQUESTED"));
        assertThat(found).isTrue();
    }

    // ─── DELETE /api/admin/users/{id}/erase (hard erase) ────────────────────

    @Test
    @DisplayName("DELETE /api/admin/users/{id}/erase: admin → 204 + PII wiped in DB")
    void adminErase_wipesAllPiiFields() throws Exception {
        mockMvc.perform(delete("/api/admin/users/" + targetUserId + "/erase")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        User erased = userRepository.findById(targetUserId).orElseThrow();
        // PII fields must be null / sentinel
        assertThat(erased.getEmail()).isNull();
        assertThat(erased.getFirstName()).isNull();
        assertThat(erased.getLastName()).isNull();
        assertThat(erased.getPassword()).isEqualTo("[ERASED]");
        // Username renamed to deleted_{id}
        assertThat(erased.getUsername()).isEqualTo("deleted_" + targetUserId);
        // Timestamps set
        assertThat(erased.getDeletedAt()).isNotNull();
        // Account is disabled
        assertThat(erased.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("DELETE /api/admin/users/{id}/erase: non-admin → 403 Forbidden")
    void adminErase_nonAdmin_returns403() throws Exception {
        mockMvc.perform(delete("/api/admin/users/" + targetUserId + "/erase")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("DELETE /api/admin/users/{id}/erase: audit event ACCOUNT_ERASED is recorded")
    void adminErase_auditEventRecorded() throws Exception {
        mockMvc.perform(delete("/api/admin/users/" + targetUserId + "/erase")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        // Audit row is written under "deleted_{id}" after erasure
        String erasedUsername = "deleted_" + targetUserId;
        boolean found = auditEventRepository.findAll().stream()
                .anyMatch(e -> e.getUsername().equals(erasedUsername)
                        && e.getEventType().equals("ACCOUNT_ERASED"));
        assertThat(found).isTrue();
    }

    // ─── Scheduled erasure job ────────────────────────────────────────────────

    @Test
    @DisplayName("scheduledErasure: account past retention window → PII erased automatically")
    void scheduledErasure_pastRetentionWindow_erasesAccount() {
        // Simulate a deletion request that was made 31 days ago
        User user = userRepository.findByUsername("jatin").orElseThrow();
        user.setEnabled(false);
        user.setDeletionRequestedAt(java.time.LocalDateTime.now()
                .minusDays(AccountErasureService.RETENTION_DAYS + 1));
        userRepository.save(user);

        // Trigger the scheduled job directly
        accountErasureService.scheduledErasure();

        User erased = userRepository.findById(targetUserId).orElseThrow();
        assertThat(erased.getDeletedAt()).isNotNull();
        assertThat(erased.getPassword()).isEqualTo("[ERASED]");
        assertThat(erased.getUsername()).isEqualTo("deleted_" + targetUserId);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private String registerAndGetToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest(username, password))))
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
