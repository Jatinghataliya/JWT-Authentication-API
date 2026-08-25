package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
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

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for DemoController.
 *
 * Tests cover:
 *  - Accessing protected endpoints without a token → 401
 *  - USER role accessing /user/me and /user/greet → 200
 *  - USER role accessing /admin/dashboard → 403
 *  - Sending an invalid token → 401
 */
@SpringBootTest
@AutoConfigureMockMvc
class DemoControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;

    private String userToken;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();
        userToken = registerAndLogin("jatin", "secret123");
    }

    // ─── No token (unauthenticated) ──────────────────────────────────────────

    @Test
    @DisplayName("GET /user/me: no token → 401 Unauthorized")
    void getUserMe_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/user/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /user/greet: no token → 401 Unauthorized")
    void getUserGreet_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/user/greet"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /admin/dashboard: no token → 401 Unauthorized")
    void getAdminDashboard_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    // ─── Valid USER token ────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /user/me: valid USER token → 200 with username and authorities")
    void getUserMe_validToken_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("jatin"))
                .andExpect(jsonPath("$.authorities").value(containsString("ROLE_USER")))
                .andExpect(jsonPath("$.message").value("You are authenticated!"));
    }

    @Test
    @DisplayName("GET /user/greet: valid USER token → 200 with greeting message")
    void getUserGreet_validToken_returns200() throws Exception {
        mockMvc.perform(get("/api/user/greet")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(containsString("jatin")))
                .andExpect(jsonPath("$.message").value(containsString("JWT is valid")));
    }

    @Test
    @DisplayName("GET /admin/dashboard: USER token → 403 Forbidden (not ADMIN)")
    void getAdminDashboard_userToken_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // ─── Invalid token ───────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /user/me: malformed token → 401 Unauthorized")
    void getUserMe_malformedToken_returns401() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer this.is.not.valid"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /user/me: token missing Bearer prefix → 401 Unauthorized")
    void getUserMe_missingBearerPrefix_returns401() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", userToken))   // no "Bearer " prefix
                .andExpect(status().isUnauthorized());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Registers a user, logs in, and returns the accessToken.
     * Shared setup used by all tests that need a valid token.
     */
    private String registerAndLogin(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        String body = objectMapper.writeValueAsString(req);

        // Register
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());

        // Login and extract token
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponse.class);
        return response.getAccessToken();
    }
}
