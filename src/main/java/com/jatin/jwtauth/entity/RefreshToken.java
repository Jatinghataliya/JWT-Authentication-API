package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * RefreshToken — persisted, long-lived token paired with a User.
 *
 * Key learning points:
 *  - The access token is short-lived (e.g. 15 min) and stateless (JWT).
 *  - The refresh token is long-lived (e.g. 7 days), stored in DB so it
 *    can be revoked at any time (logout, admin action, etc.).
 *  - One-to-one with User: a new login replaces any previous refresh token.
 */
@Entity
@Table(name = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The opaque token value sent to the client (UUID, not a JWT). */
    @Column(nullable = false, unique = true)
    private String token;

    /** Owning user — each user has at most one active refresh token. */
    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    private User user;

    /** Absolute expiry — checked on every /refresh call. */
    @Column(nullable = false)
    private Instant expiryDate;
}
