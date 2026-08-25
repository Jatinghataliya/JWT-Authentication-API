package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.ChangeRoleRequest;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Role-based Authorization Integration Tests.
 *
 * Verifies that:
 *  - USER  can access /api/user/** only
 *  - MODERATOR can access /api/user/** and /api/moderator/**
 *  - ADMIN can access all: /api/user/**, /api/moderator/**, /api/admin/**
 *  - Role escalation is blocked (USER → admin endpoints → 403)
 */
@SpringBootTest
@AutoConfigureMockMvc
class RoleBasedControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;

    private String userToken;
    private String moderatorToken;
    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();

        // Register a plain USER via the public endpoint
        userToken = registerAndLogin("user1", "password1");

        // Create MODERATOR and ADMIN via admin bootstrap — we seed them directly to avoid
        // chicken-and-egg problem (no admin exists yet to call /api/admin/users).
        // In production you'd seed an initial admin via a DataInitializer or DB migration.
        seedUserWithRole("moderator1", "password1", User.Role.MODERATOR);
        seedUserWithRole("admin1", "password1", User.Role.ADMIN);
        moderatorToken = loginAndGetToken("moderator1", "password1");
        adminToken    = loginAndGetToken("admin1", "password1");
    }

    // ═══════════════════════════════════════════════════════════════════
    // /api/user/** — accessible by all authenticated users
    // ═══════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("USER: GET /api/user/me → 200 with own profile")
    void user_getMe_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user1"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.id").isNumber());
    }

    @Test
    @DisplayName("USER: GET /api/user/dashboard → 200")
    void user_getDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/user/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("USER level"));
    }

    @Test
    @DisplayName("MODERATOR: GET /api/user/me → 200 (moderator can also access user endpoints)")
    void moderator_getMe_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("moderator1"))
                .andExpect(jsonPath("$.role").value("MODERATOR"));
    }

    @Test
    @DisplayName("ADMIN: GET /api/user/me → 200 (admin can also access user endpoints)")
    void admin_getMe_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin1"))
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // /api/moderator/** — accessible by MODERATOR and ADMIN only
    // ═══════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("USER: GET /api/moderator/dashboard → 403 Forbidden")
    void user_moderatorDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/moderator/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("MODERATOR: GET /api/moderator/dashboard → 200")
    void moderator_moderatorDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/moderator/dashboard")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("MODERATOR level"));
    }

    @Test
    @DisplayName("MODERATOR: GET /api/moderator/users → 200 with user list")
    void moderator_listUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/moderator/users")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))))
                .andExpect(jsonPath("$[*].username", hasItems("user1", "moderator1", "admin1")));
    }

    @Test
    @DisplayName("ADMIN: GET /api/moderator/users → 200 (admin has moderator access too)")
    void admin_moderatorUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/moderator/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    // ═══════════════════════════════════════════════════════════════════
    // /api/admin/** — ADMIN only
    // ═══════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("USER: GET /api/admin/dashboard → 403 Forbidden")
    void user_adminDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("MODERATOR: GET /api/admin/dashboard → 403 Forbidden")
    void moderator_adminDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ADMIN: GET /api/admin/dashboard → 200")
    void admin_adminDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("ADMIN level — full control"));
    }

    @Test
    @DisplayName("ADMIN: GET /api/admin/users → 200 with all users, no passwords")
    void admin_listAllUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))))
                .andExpect(jsonPath("$[*].password").doesNotExist());
    }

    @Test
    @DisplayName("ADMIN: POST /api/admin/users → 201 creates MODERATOR user")
    void admin_createModeratorUser_returns201() throws Exception {
        AdminRegisterRequest req = new AdminRegisterRequest();
        req.setUsername("newmod");
        req.setPassword("password1");
        req.setRole(User.Role.MODERATOR);

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("newmod"))
                .andExpect(jsonPath("$.role").value("MODERATOR"));
    }

    @Test
    @DisplayName("USER: POST /api/admin/users → 403 (cannot create users)")
    void user_createUser_returns403() throws Exception {
        AdminRegisterRequest req = new AdminRegisterRequest();
        req.setUsername("hacker");
        req.setPassword("password1");
        req.setRole(User.Role.ADMIN);

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ADMIN: PATCH /api/admin/users/{id}/role → 200 changes role to MODERATOR")
    void admin_changeRole_returns200() throws Exception {
        // Get user1's id
        Long userId = userRepository.findByUsername("user1").orElseThrow().getId();

        ChangeRoleRequest req = new ChangeRoleRequest();
        req.setRole(User.Role.MODERATOR);

        mockMvc.perform(patch("/api/admin/users/" + userId + "/role")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("MODERATOR"))
                .andExpect(jsonPath("$.username").value("user1"));
    }

    @Test
    @DisplayName("ADMIN: DELETE /api/admin/users/{id} → 204 No Content")
    void admin_deleteUser_returns204() throws Exception {
        Long userId = userRepository.findByUsername("user1").orElseThrow().getId();

        mockMvc.perform(delete("/api/admin/users/" + userId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("ADMIN: DELETE /api/admin/users/{id} non-existent → 400")
    void admin_deleteNonExistentUser_returns400() throws Exception {
        mockMvc.perform(delete("/api/admin/users/99999")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("No token: GET /api/admin/dashboard → 401")
    void noToken_adminDashboard_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════

    /** Register via public endpoint and return JWT. */
    private String registerAndLogin(String username, String password) throws Exception {
        AuthRequest req = buildAuthRequest(username, password);
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());
        return loginAndGetToken(username, password);
    }

    /** Login and extract JWT from response. */
    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();
    }

    /** Directly seed a user with a specific role — bypasses the public register endpoint. */
    private void seedUserWithRole(String username, String password, User.Role role) {
        com.jatin.jwtauth.entity.User user = com.jatin.jwtauth.entity.User.builder()
                .username(username)
                .password(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(password))
                .role(role)
                .build();
        userRepository.save(user);
    }

    private AuthRequest buildAuthRequest(String username, String password) {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }
}
