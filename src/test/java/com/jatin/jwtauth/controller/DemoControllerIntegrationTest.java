package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
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

import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class DemoControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;

    private String userToken;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();
        userToken = registerAndLogin("jatin", "secret123");
    }

    @Test
    @DisplayName("GET /user/me: no token → 401 Unauthorized")
    void getUserMe_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/user/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /user/dashboard: no token → 401 Unauthorized")
    void getUserGreet_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/user/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /admin/dashboard: no token → 401 Unauthorized")
    void getAdminDashboard_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /user/me: valid USER token → 200 with username and roles array")
    void getUserMe_validToken_returns200() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("jatin"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    @DisplayName("GET /user/dashboard: valid USER token → 200 with welcome message")
    void getUserGreet_validToken_returns200() throws Exception {
        mockMvc.perform(get("/api/user/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(containsString("jatin")));
    }

    @Test
    @DisplayName("GET /admin/dashboard: USER token → 403 Forbidden (not ADMIN)")
    void getAdminDashboard_userToken_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

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
                        .header("Authorization", userToken))
                .andExpect(status().isUnauthorized());
    }

    private String registerAndLogin(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        String body = objectMapper.writeValueAsString(req);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class)
                .getAccessToken();
    }
}
