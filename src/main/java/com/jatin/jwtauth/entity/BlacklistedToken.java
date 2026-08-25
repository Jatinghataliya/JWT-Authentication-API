package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * BlacklistedToken — records access tokens that have been explicitly revoked
 * (e.g. via logout) before their natural expiry.
 *
 * Key learning points:
 *  - We store the JWT ID claim ("jti") rather than the full token string.
 *    The jti is a small UUID; the full token can be kilobytes.
 *  - expiresAt mirrors the token's own "exp" claim so the cleanup scheduler
 *    can safely delete rows that are already past natural expiry.
 *  - This table is append-only; nothing is ever updated.
 */
@Entity
@Table(name = "blacklisted_tokens", indexes = {
        @Index(name = "idx_blacklisted_jti", columnList = "jti", unique = true)
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BlacklistedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The JWT ID claim — unique identifier of the revoked access token. */
    @Column(nullable = false, unique = true, length = 36)
    private String jti;

    /** When the access token naturally expires — used by the cleanup scheduler. */
    @Column(nullable = false)
    private Instant expiresAt;
}
