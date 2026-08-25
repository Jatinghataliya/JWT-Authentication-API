package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * LoginAttempt — immutable audit record of every login attempt.
 *
 * Key learning points:
 *  - Records both successful and failed attempts so admins can audit
 *    login history and brute-force detection logic has a data source.
 *  - ipAddress lets us detect distributed brute-force attacks across
 *    multiple usernames from the same origin.
 *  - attemptedAt is set at INSERT; nothing is ever updated.
 *  - The composite index (username + attemptedAt) makes the "count recent
 *    failures in the last N minutes" query fast.
 */
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_attempts_username_time", columnList = "username, attempted_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The username that was used in the attempt (may not exist in the users table). */
    @Column(nullable = false)
    private String username;

    /** IP address of the client — may be null if not available (e.g. tests). */
    @Column(name = "ip_address")
    private String ipAddress;

    /** true = login succeeded; false = wrong credentials / locked / disabled. */
    @Column(nullable = false)
    private boolean success;

    /** When the attempt was made — set at INSERT, never updated. */
    @Column(name = "attempted_at", nullable = false)
    private LocalDateTime attemptedAt;
}
