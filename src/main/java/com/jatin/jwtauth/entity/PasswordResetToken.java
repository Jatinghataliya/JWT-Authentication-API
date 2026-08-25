package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * PasswordResetToken — single-use token stored in DB for password reset flows.
 *
 * Key design decisions:
 *  1. Token is a UUID — opaque, high-entropy, not guessable.
 *  2. Expiry at 1 hour after generation — configurable via @Value if desired later.
 *  3. 'used' flag is set on redemption so the same token can't be replayed.
 *  4. @Scheduled cleanup in PasswordResetService purges expired/used rows.
 */
@Entity
@Table(name = "password_reset_tokens")
@Getter @Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    @Builder.Default
    private boolean used = false;
}
