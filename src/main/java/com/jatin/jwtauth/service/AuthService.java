package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.RefreshToken;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final LoginAttemptService loginAttemptService;
    private final EmailVerificationService emailVerificationService;

    /**
     * Register a new user.
     * Looks up the "USER" role from the DB (seeded by DataInitializer) and assigns it.
     * Issues both an access token and a refresh token on successful registration.
     * If the user provided an email, sends a verification email asynchronously.
     */
    public AuthResponse register(AuthRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username '" + request.getUsername() + "' is already taken");
        }

        Role defaultRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException(
                        "Default role 'USER' not found — check DataInitializer"));

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(defaultRole))
                .build();

        userRepository.save(user);

        // If the user has an email set, send a verification link (no-op if null)
        emailVerificationService.generateAndSendToken(user.getUsername());

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());
        return buildAuthResponse(userDetails, user.getRoles(), refreshToken.getToken());
    }

    /**
     * Authenticate an existing user and return a fresh access + refresh token pair.
     * Records every attempt (success or failure) for brute-force tracking.
     * Auto-locks the account after {@code security.max-failed-attempts} failures.
     */
    public AuthResponse login(AuthRequest request) {
        return login(request, null);
    }

    /**
     * Overload that accepts the client IP for richer audit records.
     * Called by AuthController which extracts the IP from the HTTP request.
     */
    public AuthResponse login(AuthRequest request, String ipAddress) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (AuthenticationException ex) {
            // Record failure BEFORE re-throwing so the lock can trigger
            loginAttemptService.recordFailure(request.getUsername(), ipAddress);
            throw ex;
        }

        // Successful authentication — reset failure window
        loginAttemptService.recordSuccess(request.getUsername(), ipAddress);

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());
        return buildAuthResponse(userDetails, user.getRoles(), refreshToken.getToken());
    }

    /**
     * Validate a refresh token and issue a new access token.
     * The refresh token itself is NOT rotated here (kept simple).
     * Rotation (issue new refresh token + invalidate old) can be added later.
     */
    public AuthResponse refreshAccessToken(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenService.verifyExpiration(refreshTokenValue);

        User user = refreshToken.getUser();
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        return buildAuthResponse(userDetails, user.getRoles(), refreshToken.getToken());
    }

    /**
     * Full logout:
     *  1. Blacklist the current access token's JTI so it is immediately rejected
     *     even before its 15-minute natural expiry.
     *  2. Delete the refresh token so the user cannot silently re-issue tokens.
     *
     * @param accessToken the raw JWT string from the Authorization header
     * @param username    the authenticated user's username
     */
    @Transactional
    public void logout(String accessToken, String username) {
        // 1. Blacklist the access token by its JTI
        String jti = jwtUtil.extractJti(accessToken);
        tokenBlacklistService.blacklist(jti, jwtUtil.extractExpirationInstant(accessToken));

        // 2. Delete the refresh token
        refreshTokenService.deleteByUsername(username);
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    private AuthResponse buildAuthResponse(UserDetails userDetails, Set<Role> roles, String refreshTokenValue) {
        Set<String> roleNames = roles.stream().map(Role::getName).collect(Collectors.toSet());

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("roles", roleNames);   // embed all role names in JWT

        String accessToken = jwtUtil.generateToken(extraClaims, userDetails);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationMs())
                .username(userDetails.getUsername())
                .roles(roleNames)
                .build();
    }
}
