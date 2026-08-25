package com.jatin.jwtauth.filter;

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
}
