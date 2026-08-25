package com.jatin.jwtauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * JwtUtil — stateless token generation and validation.
 *
 * Key learning points:
 *  1. We sign with a symmetric HMAC-SHA256 key stored as an env variable.
 *  2. Tokens carry the username as the "subject" claim.
 *  3. Every token now also carries a unique "jti" (JWT ID) claim — a UUID
 *     that lets the server individually revoke a specific token without
 *     invalidating all tokens for that user.
 *  4. No server-side session — any instance that shares the same secret can validate.
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    // ─── Public API ───────────────────────────────────────────────────────────

    /** Generate a token for the given UserDetails (stores username as subject). */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /** Generate a token with extra claims (e.g. roles). Embeds a unique jti. */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /** Check token is valid: username matches AND token is not expired. */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /** Extract the username (subject) from the token. */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract the JWT ID ("jti") claim — the unique identifier of this token.
     * Used by the blacklist service to revoke a specific token on logout.
     */
    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    /**
     * Extract the expiration time as an {@link Instant}.
     * Used by the blacklist service to record when the entry can be pruned.
     */
    public Instant extractExpirationInstant(String token) {
        return extractClaim(token, claims -> claims.getExpiration().toInstant());
    }

    /** Return how many ms until the token expires (configured via jwt.expiration). */
    public long getExpirationMs() {
        return jwtExpiration;
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .id(UUID.randomUUID().toString())          // unique jti per token
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        // Throws JwtException subclasses if signature is wrong or token is malformed
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
