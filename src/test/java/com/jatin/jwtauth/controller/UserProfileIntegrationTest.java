package com.jatin.jwtauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.ChangePasswordRequest;
import com.jatin.jwtauth.dto.UpdateProfileRequest;
import com.jatin.jwtauth.repository.BlacklistedTokenRepository;
import com.jatin.jwtauth.repository.LoginAttemptRepository;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserProfileIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BlacklistedTokenRepository blacklistedTokenRepository;
    @Autowired private LoginAttemptRepository loginAttemptRepository;
    @MockBean  private JavaMailSender javaMailSender;

    private String accessToken;

    @BeforeEach
    void setUp() throws Exception {
        loginAttemptRepository.deleteAll();
        blacklistedTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        accessToken = registerAndGetToken("jatin", "secret123");
    }

    // ─── GET /api/user/me ────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /me: returns full profile with new fields (email/firstName/lastName are null initially)")
    void getMe_returnsFullProfile() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("jatin"))
                .andExpect(jsonPath("$.roles", hasItem("USER")))
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andExpect(jsonPath("$.updatedAt").isNotEmpty())
                .andExpect(jsonPath("$.email").isEmpty())
                .andExpect(jsonPath("$.firstName").isEmpty())
                .andExpect(jsonPath("$.lastName").isEmpty());
    }

    // ─── PUT /api/user/me ────────────────────────────────────────────────────

    @Test
    @DisplayName("PUT /me: update all profile fields → 200 with updated values")
    void updateProfile_allFields_returns200() throws Exception {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setEmail("jatin@example.com");
        req.setFirstName("Jatin");
        req.setLastName("Ghataliya");

        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("jatin@example.com"))
                .andExpect(jsonPath("$.firstName").value("Jatin"))
                .andExpect(jsonPath("$.lastName").value("Ghataliya"))
                .andExpect(jsonPath("$.username").value("jatin"));
    }

    @Test
    @DisplayName("PUT /me: partial update (only firstName) → other fields unchanged")
    void updateProfile_partialUpdate_otherFieldsUnchanged() throws Exception {
        // First set all fields
        UpdateProfileRequest full = new UpdateProfileRequest();
        full.setEmail("jatin@example.com");
        full.setFirstName("Jatin");
        full.setLastName("Ghataliya");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(full)))
                .andExpect(status().isOk());

        // Now update only firstName
        UpdateProfileRequest partial = new UpdateProfileRequest();
        partial.setFirstName("Jay");

        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(partial)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Jay"))
                .andExpect(jsonPath("$.email").value("jatin@example.com"))   // unchanged
                .andExpect(jsonPath("$.lastName").value("Ghataliya"));       // unchanged
    }

    @Test
    @DisplayName("PUT /me: invalid email format → 400 Bad Request")
    void updateProfile_invalidEmail_returns400() throws Exception {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setEmail("not-a-valid-email");

        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("email")));
    }

    @Test
    @DisplayName("PUT /me: duplicate email (taken by another user) → 400")
    void updateProfile_duplicateEmail_returns400() throws Exception {
        // Register a second user and give them the email
        String token2 = registerAndGetToken("other", "pass123");
        UpdateProfileRequest other = new UpdateProfileRequest();
        other.setEmail("shared@example.com");
        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + token2)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(other)))
                .andExpect(status().isOk());

        // Now try to claim the same email with the first user
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setEmail("shared@example.com");

        mockMvc.perform(put("/api/user/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("already in use")));
    }

    @Test
    @DisplayName("PUT /me: no token → 401 Unauthorized")
    void updateProfile_noToken_returns401() throws Exception {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setFirstName("Jatin");

        mockMvc.perform(put("/api/user/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // ─── PUT /api/user/me/password ───────────────────────────────────────────

    @Test
    @DisplayName("PUT /me/password: correct current password → 204 No Content")
    void changePassword_correct_returns204() throws Exception {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("secret123");
        req.setNewPassword("newSecret456");

        mockMvc.perform(put("/api/user/me/password")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("PUT /me/password: wrong current password → 400 Bad Request")
    void changePassword_wrongCurrent_returns400() throws Exception {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("wrong-password");
        req.setNewPassword("newSecret456");

        mockMvc.perform(put("/api/user/me/password")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Current password is incorrect")));
    }

    @Test
    @DisplayName("PUT /me/password: new password too short → 400 Bad Request")
    void changePassword_shortNewPassword_returns400() throws Exception {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("secret123");
        req.setNewPassword("abc");

        mockMvc.perform(put("/api/user/me/password")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("newPassword")));
    }

    @Test
    @DisplayName("PUT /me/password: after change, old credentials rejected on login")
    void changePassword_oldCredentialsRejected() throws Exception {
        // Change password
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("secret123");
        req.setNewPassword("newSecret456");
        mockMvc.perform(put("/api/user/me/password")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());

        // Old password should no longer work
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("jatin", "secret123"))))
                .andExpect(status().isUnauthorized());

        // New password should work
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildAuthRequest("jatin", "newSecret456"))))
                .andExpect(status().isOk());
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

    private AuthRequest buildAuthRequest(String username, String password) {
        AuthRequest req = new AuthRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }
}
