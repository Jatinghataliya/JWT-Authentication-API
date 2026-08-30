package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.entity.Role;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserSearchIntegrationTest {

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

        // Register admin + two regular users
        adminToken = registerAndGrantAdmin("searchadmin", "secret123");
        registerUser("alice", "secret123");
        registerUser("bob_user", "secret123");

        // Disable alice for filter tests
        userRepository.findByUsername("alice").ifPresent(u -> {
            u.setEnabled(false);
            userRepository.save(u);
        });

        // Set email on bob
        userRepository.findByUsername("bob_user").ifPresent(u -> {
            u.setEmail("bob@example.com");
            userRepository.save(u);
        });
    }

    // ─── /users/search ────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /users/search no filters → returns all users paged")
    void search_noFilters_returnsAll() throws Exception {
        mockMvc.perform(get("/api/admin/users/search")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3)); // admin + alice + bob
    }

    @Test
    @DisplayName("GET /users/search?username=alice → returns only alice")
    void search_byUsername_returnsMatch() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?username=alice")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("alice"));
    }

    @Test
    @DisplayName("GET /users/search?username=ob → partial match on 'bob_user'")
    void search_partialUsername_returnsMatch() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?username=ob")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("bob_user"));
    }

    @Test
    @DisplayName("GET /users/search?email=example.com → partial match by email domain")
    void search_byEmail_returnsMatch() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?email=example.com")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("bob_user"));
    }

    @Test
    @DisplayName("GET /users/search?enabled=false → returns only disabled users")
    void search_byEnabled_returnsDisabled() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?enabled=false")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("alice"));
    }

    @Test
    @DisplayName("GET /users/search?role=ADMIN → returns only admin user")
    void search_byRole_returnsAdminOnly() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?role=ADMIN")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("searchadmin"));
    }

    @Test
    @DisplayName("GET /users/search?username=nobody → empty result")
    void search_noMatch_returnsEmpty() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?username=nobody")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.content", hasSize(0)));
    }

    @Test
    @DisplayName("GET /users/search?username=alice&enabled=false → combined AND filter")
    void search_combinedFilters_returnsMatch() throws Exception {
        mockMvc.perform(get("/api/admin/users/search?username=alice&enabled=false")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].username").value("alice"));
    }

    @Test
    @DisplayName("GET /users/search without ADMIN role → 403 Forbidden")
    void search_withoutAdmin_returns403() throws Exception {
        String userToken = registerAndGetToken("regularuser", "secret123");
        mockMvc.perform(get("/api/admin/users/search")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // ─── /users/export.csv ────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /users/export.csv → Content-Type text/csv with header row")
    void exportCsv_returnsValidCsv() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/admin/users/export.csv")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("users.csv")))
                .andReturn();

        String csv = result.getResponse().getContentAsString();
        assertThat(csv).startsWith("id,username,email,firstName,lastName,enabled,accountNonLocked,emailVerified,roles,createdAt");
        assertThat(csv).contains("searchadmin");
        assertThat(csv).contains("alice");
        assertThat(csv).contains("bob_user");
    }

    @Test
    @DisplayName("GET /users/export.csv?username=alice → CSV contains only alice")
    void exportCsv_withFilter_returnsFilteredCsv() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/admin/users/export.csv?username=alice")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();

        String csv = result.getResponse().getContentAsString();
        assertThat(csv).contains("alice");
        assertThat(csv).doesNotContain("bob_user");
        assertThat(csv).doesNotContain("searchadmin");
    }

    @Test
    @DisplayName("GET /users/export.csv without ADMIN role → 403 Forbidden")
    void exportCsv_withoutAdmin_returns403() throws Exception {
        String userToken = registerAndGetToken("regularuser2", "secret123");
        mockMvc.perform(get("/api/admin/users/export.csv")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private String registerAndGetToken(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        MvcResult res = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(res.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    private void registerUser(String username, String password) throws Exception {
        registerAndGetToken(username, password);
    }

    private String registerAndGrantAdmin(String username, String password) throws Exception {
        String token = registerAndGetToken(username, password);
        userRepository.findByUsername(username).ifPresent(u -> {
            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseThrow(() -> new RuntimeException("ADMIN role not found"));
            u.getRoles().add(adminRole);
            userRepository.save(u);
        });
        return token;
    }
}
