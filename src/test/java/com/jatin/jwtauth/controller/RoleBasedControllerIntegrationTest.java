package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class RoleBasedControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private RefreshTokenRepository refreshTokenRepository;

    private String userToken;
    private String moderatorToken;
    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        // Roles are seeded by DataInitializer — do NOT delete them

        userToken     = registerAndLogin("user1", "password1");
        seedUserWithRoles("moderator1", "password1", Set.of("MODERATOR"));
        seedUserWithRoles("admin1",     "password1", Set.of("ADMIN"));
        moderatorToken = loginAndGetToken("moderator1", "password1");
        adminToken     = loginAndGetToken("admin1", "password1");
    }

    // ── /api/user/** ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("USER: GET /api/user/me → 200 with roles array")
    void user_getMe_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user1"))
                .andExpect(jsonPath("$.roles", hasItem("USER")));
    }

    @Test
    @DisplayName("USER: GET /api/user/dashboard → 200")
    void user_getDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/user/dashboard").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("USER level"));
    }

    @Test
    @DisplayName("ADMIN: GET /api/user/me → 200 (admin inherits user access)")
    void admin_getMe_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItem("ADMIN")));
    }

    // ── /api/moderator/** ─────────────────────────────────────────────────────

    @Test
    @DisplayName("USER: GET /api/moderator/dashboard → 403 Forbidden")
    void user_moderatorDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/moderator/dashboard").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("MODERATOR: GET /api/moderator/dashboard → 200")
    void moderator_moderatorDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/moderator/dashboard").header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("MODERATOR level"));
    }

    @Test
    @DisplayName("MODERATOR: GET /api/moderator/users → 200 with user list")
    void moderator_listUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/moderator/users").header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))));
    }

    // ── /api/admin/** ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("USER: GET /api/admin/dashboard → 403 Forbidden")
    void user_adminDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("MODERATOR: GET /api/admin/dashboard → 403 Forbidden")
    void moderator_adminDashboard_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard").header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ADMIN: GET /api/admin/dashboard → 200")
    void admin_adminDashboard_returns200() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access").value("ADMIN level — full control"));
    }

    @Test
    @DisplayName("ADMIN: GET /api/admin/users → 200, no passwords in response")
    void admin_listAllUsers_returns200() throws Exception {
        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))))
                .andExpect(jsonPath("$[*].password").doesNotExist());
    }

    @Test
    @DisplayName("ADMIN: POST /api/admin/users → 201 creates user with MODERATOR role")
    void admin_createUserWithRoles_returns201() throws Exception {
        AdminRegisterRequest req = new AdminRegisterRequest();
        req.setUsername("newmod");
        req.setPassword("password1");
        req.setRoles(Set.of("MODERATOR"));

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("newmod"))
                .andExpect(jsonPath("$.roles", hasItem("MODERATOR")));
    }

    @Test
    @DisplayName("ADMIN: POST /api/admin/users with multiple roles → user gets both")
    void admin_createUserWithMultipleRoles_returns201() throws Exception {
        AdminRegisterRequest req = new AdminRegisterRequest();
        req.setUsername("multiuser");
        req.setPassword("password1");
        req.setRoles(Set.of("USER", "MODERATOR"));

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles", hasSize(2)))
                .andExpect(jsonPath("$.roles", hasItems("USER", "MODERATOR")));
    }

    @Test
    @DisplayName("ADMIN: POST /api/admin/users/{id}/roles → assign extra role to user")
    void admin_assignRole_returns200() throws Exception {
        Long userId = userRepository.findByUsername("user1").orElseThrow().getId();

        AssignRoleRequest req = new AssignRoleRequest();
        req.setRoleName("MODERATOR");

        mockMvc.perform(post("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItems("USER", "MODERATOR")));
    }

    @Test
    @DisplayName("ADMIN: DELETE /api/admin/users/{id}/roles → revoke a role")
    void admin_revokeRole_returns200() throws Exception {
        Long userId = userRepository.findByUsername("user1").orElseThrow().getId();

        // Assign MODERATOR first
        AssignRoleRequest assign = new AssignRoleRequest();
        assign.setRoleName("MODERATOR");
        mockMvc.perform(post("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(assign)))
                .andExpect(status().isOk());

        // Then revoke it
        AssignRoleRequest revoke = new AssignRoleRequest();
        revoke.setRoleName("MODERATOR");
        mockMvc.perform(delete("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(revoke)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", not(hasItem("MODERATOR"))));
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
    @DisplayName("No token: GET /api/admin/dashboard → 401")
    void noToken_adminDashboard_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String registerAndLogin(String username, String pwd) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(pwd);
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());
        return loginAndGetToken(username, pwd);
    }

    private String loginAndGetToken(String username, String pwd) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(pwd);
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
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
}
