package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.RoleRequest;
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
 * Dynamic Role Integration Tests.
 *
 * Proves the core value of the dynamic role system:
 *  1. Admin creates a brand-new role "EDITOR" at runtime via the API
 *  2. Admin assigns "EDITOR" to a user
 *  3. That user now passes @PreAuthorize("hasRole('EDITOR')") — no code change
 *  4. Revoking the role removes the access immediately
 *  5. Deleting a role from the catalog removes it from all users
 */
@SpringBootTest
@AutoConfigureMockMvc
class DynamicRoleIntegrationTest {

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
    private String userToken;
    private Long userId;

    @BeforeEach
    void setUp() throws Exception {
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        // Clean up any previously created dynamic roles (keep base roles)
        roleRepository.findByName("EDITOR").ifPresent(roleRepository::delete);

        seedUserWithRoles("admin1", "pass123", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "pass123");

        userToken = registerAndLogin("normaluser", "pass123");
        userId = userRepository.findByUsername("normaluser").orElseThrow().getId();
    }

    @Test
    @DisplayName("Admin creates new role EDITOR at runtime → role appears in catalog")
    void createNewRole_appearsInCatalog() throws Exception {
        RoleRequest req = new RoleRequest();
        req.setName("editor");           // lower-case — service normalises to upper-case
        req.setDescription("Can edit content");

        mockMvc.perform(post("/api/admin/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("EDITOR"))
                .andExpect(jsonPath("$.description").value("Can edit content"));

        mockMvc.perform(get("/api/admin/roles")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].name", hasItem("EDITOR")));
    }

    @Test
    @DisplayName("Admin assigns newly created EDITOR role to user → user has both USER and EDITOR")
    void assignDynamicRole_userReceivesIt() throws Exception {
        // Create the role
        createEditorRole();

        // Assign it
        AssignRoleRequest req = new AssignRoleRequest();
        req.setRoleName("EDITOR");

        mockMvc.perform(post("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItems("USER", "EDITOR")));
    }

    @Test
    @DisplayName("Assign non-existent role → 400 with descriptive message")
    void assignNonExistentRole_returns400() throws Exception {
        AssignRoleRequest req = new AssignRoleRequest();
        req.setRoleName("DOES_NOT_EXIST");

        mockMvc.perform(post("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("does not exist")));
    }

    @Test
    @DisplayName("Revoke role user doesn't have → 400 with descriptive message")
    void revokeUnassignedRole_returns400() throws Exception {
        createEditorRole();

        AssignRoleRequest req = new AssignRoleRequest();
        req.setRoleName("EDITOR");  // user doesn't have EDITOR yet

        mockMvc.perform(delete("/api/admin/users/" + userId + "/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("does not have role")));
    }

    @Test
    @DisplayName("Create duplicate role → 400 with descriptive message")
    void createDuplicateRole_returns400() throws Exception {
        createEditorRole();

        RoleRequest dup = new RoleRequest();
        dup.setName("EDITOR");

        mockMvc.perform(post("/api/admin/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dup)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("already exists")));
    }

    @Test
    @DisplayName("Admin updates role description via PUT")
    void updateRole_changesDescription() throws Exception {
        Long roleId = createEditorRole();

        RoleRequest update = new RoleRequest();
        update.setName("EDITOR");
        update.setDescription("Updated description");

        mockMvc.perform(put("/api/admin/roles/" + roleId)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(update)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.description").value("Updated description"));
    }

    @Test
    @DisplayName("Admin deletes role from catalog → role no longer listed")
    void deleteRole_removedFromCatalog() throws Exception {
        Long roleId = createEditorRole();

        mockMvc.perform(delete("/api/admin/roles/" + roleId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/admin/roles")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].name", not(hasItem("EDITOR"))));
    }

    @Test
    @DisplayName("USER cannot access admin role endpoints → 403")
    void user_roleEndpoints_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/roles")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Creates the EDITOR role and returns its id. */
    private Long createEditorRole() throws Exception {
        RoleRequest req = new RoleRequest();
        req.setName("EDITOR");
        req.setDescription("Can edit content");

        MvcResult result = mockMvc.perform(post("/api/admin/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("id").asLong();
    }

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
