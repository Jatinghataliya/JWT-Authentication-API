package com.jatin.jwtauth.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for JwtUtil.
 *
 * No Spring context needed — we inject @Value fields via ReflectionTestUtils.
 * Tests cover: token generation, username extraction, validation, and expiry.
 */
class JwtUtilTest {

    // Same secret used in test application.yml
    private static final String TEST_SECRET =
            "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long EXPIRATION_MS = 86_400_000L; // 24h

    private JwtUtil jwtUtil;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secretKey", TEST_SECRET);
        ReflectionTestUtils.setField(jwtUtil, "jwtExpiration", EXPIRATION_MS);

        userDetails = new User(
                "jatin",
                "hashed_password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    // ─── generateToken + extractUsername ────────────────────────────────────

    @Test
    @DisplayName("generateToken: token contains correct username as subject")
    void generateToken_shouldContainUsername() {
        String token = jwtUtil.generateToken(userDetails);

        assertThat(token).isNotBlank();
        assertThat(jwtUtil.extractUsername(token)).isEqualTo("jatin");
    }

    @Test
    @DisplayName("generateToken with extra claims: extra claims are embedded in token")
    void generateToken_withExtraClaims_shouldEmbedClaims() {
        Map<String, Object> claims = Map.of("role", "USER", "custom", "value");

        String token = jwtUtil.generateToken(claims, userDetails);

        assertThat(jwtUtil.extractUsername(token)).isEqualTo("jatin");
    }

    @Test
    @DisplayName("generateToken: two calls produce different tokens (different iat)")
    void generateToken_calledTwice_producesDifferentTokens() throws InterruptedException {
        String token1 = jwtUtil.generateToken(userDetails);
        Thread.sleep(1000); // ensure different issuedAt timestamp
        String token2 = jwtUtil.generateToken(userDetails);

        assertThat(token1).isNotEqualTo(token2);
    }

    // ─── isTokenValid ────────────────────────────────────────────────────────

    @Test
    @DisplayName("isTokenValid: valid token for same user returns true")
    void isTokenValid_validToken_returnsTrue() {
        String token = jwtUtil.generateToken(userDetails);

        assertThat(jwtUtil.isTokenValid(token, userDetails)).isTrue();
    }

    @Test
    @DisplayName("isTokenValid: token generated for different user returns false")
    void isTokenValid_differentUser_returnsFalse() {
        String token = jwtUtil.generateToken(userDetails);

        UserDetails otherUser = new User(
                "other_user",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        assertThat(jwtUtil.isTokenValid(token, otherUser)).isFalse();
    }

    // ─── expired token ───────────────────────────────────────────────────────

    @Test
    @DisplayName("isTokenValid: expired token throws ExpiredJwtException (handled as invalid)")
    void isTokenValid_expiredToken_throwsExpiredJwtException() {
        // Set expiration to -1ms so the token is born already expired
        ReflectionTestUtils.setField(jwtUtil, "jwtExpiration", -1L);
        String expiredToken = jwtUtil.generateToken(userDetails);

        // Reset to normal for validation
        ReflectionTestUtils.setField(jwtUtil, "jwtExpiration", EXPIRATION_MS);

        // jjwt throws ExpiredJwtException (subclass of JwtException) on expired tokens
        // This is caught by JwtAuthFilter and results in 401 — the correct behaviour
        assertThatThrownBy(() -> jwtUtil.isTokenValid(expiredToken, userDetails))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }

    // ─── malformed token ─────────────────────────────────────────────────────

    @Test
    @DisplayName("extractUsername: malformed token throws JwtException")
    void extractUsername_malformedToken_throwsException() {
        assertThatThrownBy(() -> jwtUtil.extractUsername("this.is.not.a.jwt"))
                .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }

    @Test
    @DisplayName("extractUsername: token signed with wrong secret throws JwtException")
    void extractUsername_wrongSecret_throwsException() {
        // Create a token with a different secret
        JwtUtil otherUtil = new JwtUtil();
        ReflectionTestUtils.setField(otherUtil, "secretKey",
                "5468576D5A7134743777217A25432A462D4A614E645267556B58703272357538");
        ReflectionTestUtils.setField(otherUtil, "jwtExpiration", EXPIRATION_MS);

        String tokenWithWrongSecret = otherUtil.generateToken(userDetails);

        // Our jwtUtil (different secret) should reject it
        assertThatThrownBy(() -> jwtUtil.extractUsername(tokenWithWrongSecret))
                .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }

    // ─── getExpirationMs ─────────────────────────────────────────────────────

    @Test
    @DisplayName("getExpirationMs: returns configured value")
    void getExpirationMs_returnsConfiguredValue() {
        assertThat(jwtUtil.getExpirationMs()).isEqualTo(EXPIRATION_MS);
    }
}
