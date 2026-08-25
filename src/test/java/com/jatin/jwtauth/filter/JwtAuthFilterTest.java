package com.jatin.jwtauth.filter;

import com.jatin.jwtauth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwtAuthFilter.
 *
 * Uses Spring's MockHttpServletRequest/Response — no web server needed.
 * Tests cover: missing header, invalid token, valid token, already-authenticated context.
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock private JwtUtil jwtUtil;
    @Mock private UserDetailsService userDetailsService;
    @Mock private FilterChain filterChain;

    @InjectMocks
    private JwtAuthFilter jwtAuthFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        userDetails = new User(
                "jatin",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ─── No Authorization header ─────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: no Authorization header → passes through, no auth set")
    void filter_noHeader_passesThrough() throws Exception {
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(jwtUtil);
    }

    @Test
    @DisplayName("doFilterInternal: Authorization header without Bearer prefix → passes through")
    void filter_nonBearerHeader_passesThrough() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtUtil);
    }

    // ─── Valid token ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: valid Bearer token → sets authentication in SecurityContext")
    void filter_validToken_setsAuthentication() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt.token");

        when(jwtUtil.extractUsername("valid.jwt.token")).thenReturn("jatin");
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(userDetails);
        when(jwtUtil.isTokenValid("valid.jwt.token", userDetails)).thenReturn(true);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("jatin");
        verify(filterChain).doFilter(request, response);
    }

    // ─── Invalid / expired token ─────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: invalid token → returns 401, does not continue chain")
    void filter_invalidToken_returns401() throws Exception {
        request.addHeader("Authorization", "Bearer bad.token");

        when(jwtUtil.extractUsername("bad.token"))
                .thenThrow(new JwtException("Malformed token"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentAsString()).contains("Invalid or expired JWT token");
        verify(filterChain, never()).doFilter(any(), any());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("doFilterInternal: token fails isTokenValid → no auth set, chain continues")
    void filter_tokenFailsValidation_noAuthSet() throws Exception {
        request.addHeader("Authorization", "Bearer expired.token");

        when(jwtUtil.extractUsername("expired.token")).thenReturn("jatin");
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(userDetails);
        when(jwtUtil.isTokenValid("expired.token", userDetails)).thenReturn(false);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    // ─── Already authenticated ───────────────────────────────────────────────

    @Test
    @DisplayName("doFilterInternal: SecurityContext already has auth → skips token processing")
    void filter_alreadyAuthenticated_skipsProcessing() throws Exception {
        request.addHeader("Authorization", "Bearer some.token");

        // Pre-populate SecurityContext — simulates re-entrant or already-auth request
        when(jwtUtil.extractUsername("some.token")).thenReturn("jatin");
        var existingAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "jatin", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(existingAuth);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // UserDetailsService should NOT be called since auth is already set
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain).doFilter(request, response);
    }
}
