package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.RefreshToken;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * RefreshTokenService — manages the lifecycle of refresh tokens.
 *
 * Key learning points:
 *  - createRefreshToken() deletes any old token for the user first (one active token rule).
 *  - verifyExpiration() throws a clear exception so the client knows to re-login.
 *  - deleteByUser() is the "logout" operation — the token becomes immediately invalid.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${jwt.refresh-expiration:604800000}") // default 7 days in ms
    private long refreshExpirationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    /**
     * Creates (or replaces) a refresh token for the given username.
     * The old token is deleted first so each user has exactly one active token.
     */
    @Transactional
    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // Delete existing token (if any) — entity-level delete keeps Hibernate L1 cache consistent
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);
        refreshTokenRepository.flush();

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshExpirationMs))
                .build();

        return refreshTokenRepository.save(token);
    }

    /**
     * Looks up the token string and verifies it has not expired.
     *
     * @throws IllegalArgumentException if the token does not exist or has expired.
     */
    public RefreshToken verifyExpiration(String tokenValue) {
        RefreshToken token = refreshTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Refresh token not found — please log in again"));

        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new IllegalArgumentException(
                    "Refresh token has expired — please log in again");
        }

        return token;
    }

    /** Invalidates all refresh tokens for the user (called on logout). */
    @Transactional
    public void deleteByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);
    }
}
