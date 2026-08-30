package com.jatin.jwtauth.filter;

import com.jatin.jwtauth.config.PasswordPolicyConfig;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.TokenBlacklistService;
import com.jatin.jwtauth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * JwtAuthFilter — runs once per request (OncePerRequestFilter).
 *
 * Key learning steps:
 *  1. Read the "Authorization: Bearer <token>" header.
 *  2. Extract username from the token using JwtUtil.
 *  3. Check the token's JTI against the blacklist — reject if revoked.
 *  4. Load UserDetails from DB.
 *  5. Validate the token against the loaded UserDetails.
 *  6. Set Authentication in the SecurityContext so Spring Security
 *     treats the request as authenticated — no session needed.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;
    private final PasswordPolicyConfig passwordPolicyConfig;

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTH_HEADER = "Authorization";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader(AUTH_HEADER);

        // 1. No Bearer token → pass through (Spring Security will reject if endpoint is protected)
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract token (strip "Bearer " prefix)
        final String jwt = authHeader.substring(BEARER_PREFIX.length());

        try {
            final String username = jwtUtil.extractUsername(jwt);

            // 3. Check JTI blacklist — token was explicitly revoked (e.g. logout)
            final String jti = jwtUtil.extractJti(jwt);
            if (tokenBlacklistService.isBlacklisted(jti)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Token has been revoked\"}");
                return;
            }

            // 4. Only authenticate if not already set in context
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 5. Validate token (signature + expiry)
                if (jwtUtil.isTokenValid(jwt, userDetails)) {

                    // 5a. Password-expiry check — skip for password-change / reset endpoints
                    //     so users can still change their expired password
                    if (isPasswordExpired(username, request)) {
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.setContentType("application/json");
                        response.getWriter().write(
                                "{\"status\":403,\"error\":\"PASSWORD_EXPIRED\"," +
                                "\"message\":\"Your password has expired. Please change it via PUT /api/user/me/password\"}");
                        return;
                    }

                    // 6. Build authentication token and store in SecurityContext
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,                        // credentials null — password not needed after auth
                                    userDetails.getAuthorities()
                            );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (JwtException ex) {
            // Invalid / expired token — don't authenticate; let the request flow
            // Spring Security will return 401 for protected endpoints
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid or expired JWT token");
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Returns true when the policy has expiryDays > 0 AND the user's
     * passwordChangedAt is older than expiryDays.
     * Skips the check for password-change and reset endpoints so users
     * can still update an expired password without being blocked.
     */
    private boolean isPasswordExpired(String username, HttpServletRequest request) {
        int expiryDays = passwordPolicyConfig.getExpiryDays();
        if (expiryDays <= 0) return false;                          // expiry disabled

        // Allow through: password-change, password-reset, logout
        String path = request.getRequestURI();
        if (path.contains("/me/password") ||
            path.contains("/reset-password") ||
            path.contains("/forgot-password") ||
            path.contains("/logout")) {
            return false;
        }

        return userRepository.findByUsername(username)
                .map(User::getPasswordChangedAt)
                .map(changed -> changed.isBefore(LocalDateTime.now().minusDays(expiryDays)))
                .orElse(false);   // null passwordChangedAt → treat as not expired (legacy users)
    }
}
