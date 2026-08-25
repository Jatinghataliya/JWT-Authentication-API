package com.jatin.jwtauth.security;

import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.RefreshTokenService;
import com.jatin.jwtauth.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * OAuth2SuccessHandler — converts a successful OAuth2 authentication into a
 * JWT access + refresh token pair and redirects the browser to the frontend
 * with the tokens as query parameters.
 *
 * Key learning points:
 *  1. After Google redirects back to our /login/oauth2/code/google callback, Spring
 *     Security calls this handler.
 *  2. We look up the internal User by email (provisioned by OAuth2UserService) to
 *     get their roles for the JWT claims.
 *  3. The frontend URL is configurable via app.oauth2.redirect-uri so it can point
 *     to a React/Angular SPA in production.
 *  4. Tokens are passed as query params here for simplicity; a production app might
 *     prefer a short-lived one-time code exchanged server-side for better security.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    @Value("${app.oauth2.redirect-uri:http://localhost:3000/oauth2/callback}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttributes().get("email");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("User not found after OAuth2 provisioning: " + email));

        // Build JWT with roles
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles().stream()
                .map(r -> r.getName())
                .collect(Collectors.toSet()));

        // Use UserDetails wrapper for JWT generation
        org.springframework.security.core.userdetails.User springUser =
                new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        user.getRoles().stream()
                                .map(r -> new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + r.getName()))
                                .collect(Collectors.toList())
                );

        String accessToken  = jwtUtil.generateToken(claims, springUser);
        String refreshToken = refreshTokenService.createRefreshToken(user.getUsername()).getToken();

        String targetUrl = redirectUri
                + "?accessToken=" + accessToken
                + "&refreshToken=" + refreshToken;

        log.info("OAuth2SuccessHandler: redirecting user '{}' to {}", email, redirectUri);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
