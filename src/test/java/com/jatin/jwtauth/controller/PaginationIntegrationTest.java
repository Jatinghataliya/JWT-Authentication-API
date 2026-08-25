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

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 11 — Pagination for Admin List Endpoints.
 *
 * Tests cover GET /api/admin/users/paged and GET /api/admin/audit/paged.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PaginationIntegrationTest {

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
    @MockBean  private JavaMailSender javaMailSender;

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        rateLimitService.reset();
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        auditEventRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Seed 3 users (admin + 2 regular) so we can test pagination
        seedUserWithRoles("admin1", "adminpass", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "adminpass");

        // Register 2 more users
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("alpha", "pass1234"))))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("beta", "pass1234"))))
                .andExpect(status().isCreated());
    }

    // ─── GET /api/admin/users/paged ──────────────────────────────────────────

    @Test
    @DisplayName("GET /users/paged: returns correct page metadata")
    void getUsersPaged_returnsMetadata() throws Exception {
        mockMvc.perform(get("/api/admin/users/paged")
                        .param("page", "0")
                        .param("size", "2")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.content", hasSize(2)));
    }

    @Test
    @DisplayName("GET /users/paged: second page returns remaining users")
    void getUsersPaged_secondPage_returnsRemaining() throws Exception {
        mockMvc.perform(get("/api/admin/users/paged")
                        .param("page", "1")
                        .param("size", "2")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.last").value(true));
    }

    @Test
    @DisplayName("GET /users/paged: non-admin returns 403")
    void getUsersPaged_nonAdmin_returns403() throws Exception {
        MvcResult r = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("regularuser", "pass1234"))))
                .andExpect(status().isCreated())
                .andReturn();
        String userToken = objectMapper.readValue(r.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();

        mockMvc.perform(get("/api/admin/users/paged")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // ─── GET /api/admin/audit/paged ──────────────────────────────────────────

    @Test
    @DisplayName("GET /audit/paged: returns paginated audit events with metadata")
    void getAuditPaged_returnsMetadata() throws Exception {
        // audit events were created during setUp (login, register x2)
        // Count may vary; just verify the structure is correct
        mockMvc.perform(get("/api/admin/audit/paged")
                        .param("page", "0")
                        .param("size", "2")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.content", hasSize(lessThanOrEqualTo(2))))
                .andExpect(jsonPath("$.totalPages").isNumber());
    }

    @Test
    @DisplayName("GET /audit/paged: filter by username returns only matching events")
    void getAuditPaged_filterByUsername_returnsFiltered() throws Exception {
        mockMvc.perform(get("/api/admin/audit/paged")
                        .param("username", "alpha")
                        .param("page", "0")
                        .param("size", "10")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[*].username", everyItem(is("alpha"))));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private void seedUserWithRoles(String username, String password, Set<String> roleNames) {
        Set<Role> roles = new java.util.HashSet<>();
        for (String rn : roleNames) {
            roles.add(roleRepository.findByName(rn).orElseThrow());
        }
        userRepository.save(User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(roles)
                .build());
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult r = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readValue(r.getResponse().getContentAsString(), AuthResponse.class).getAccessToken();
    }

    private AuthRequest authReq(String username, String password) {
        AuthRequest r = new AuthRequest();
        r.setUsername(username);
        r.setPassword(password);
        return r;
    }
}
