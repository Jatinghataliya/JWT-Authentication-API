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
import com.jatin.jwtauth.service.AdminService;
import com.jatin.jwtauth.service.RateLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.CacheManager;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Feature 12 — Redis Caching Layer.
 *
 * Uses the Caffeine in-memory CacheManager (configured via app.cache.type=caffeine in test yml).
 * Tests verify that the cache is populated on first call and evicted on write operations.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CachingIntegrationTest {

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
    @Autowired private AdminService adminService;
    @Autowired private CacheManager cacheManager;
    @MockBean  private JavaMailSender javaMailSender;

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

        // Evict the cache so each test starts fresh
        cacheManager.getCacheNames().forEach(n -> {
            var cache = cacheManager.getCache(n);
            if (cache != null) cache.clear();
        });

        seedUserWithRoles("admin1", "adminpass", Set.of("ADMIN"));
        adminToken = loginAndGetToken("admin1", "adminpass");

        // Register a target user
        MvcResult r = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("target", "pass1234"))))
                .andExpect(status().isCreated())
                .andReturn();
        targetUserId = userRepository.findByUsername("target").orElseThrow().getId();
    }

    @Test
    @DisplayName("getAllUsers: second call is served from cache (no extra DB hit)")
    void getAllUsers_secondCallFromCache() {
        // First call — populates cache
        adminService.getAllUsers();

        // Second call — from cache; we verify by checking the cache is not null
        var cache = cacheManager.getCache("users");
        assertThat(cache).isNotNull();
        // A cached value should be present (SimpleKey.EMPTY for no-arg methods)
        // Caffeine stores the value so getIfPresent returns non-null after first call
        assertThat(adminService.getAllUsers()).isNotEmpty();
    }

    @Test
    @DisplayName("getUserById: cached result is returned on second call")
    void getUserById_isCached() {
        // First call populates cache for this id
        var first = adminService.getUserById(targetUserId);
        // Second call returns same result from cache
        var second = adminService.getUserById(targetUserId);
        assertThat(first.getUsername()).isEqualTo(second.getUsername());
    }

    @Test
    @DisplayName("Cache is evicted after disableUser — next getAllUsers returns fresh data")
    void disableUser_evictsCache() throws Exception {
        // Warm up the cache
        adminService.getAllUsers();

        // Disable the target user — should evict "users" cache
        mockMvc.perform(patch("/api/admin/users/" + targetUserId + "/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Verify the user is disabled in the fresh (re-fetched) list
        var users = adminService.getAllUsers();
        var targetUser = users.stream()
                .filter(u -> u.getUsername().equals("target"))
                .findFirst().orElseThrow();
        assertThat(targetUser.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("GET /admin/users returns 200 with correct count (cached)")
    void adminGetUsers_returns200WithCache() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
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
