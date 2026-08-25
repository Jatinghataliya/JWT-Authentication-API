package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * AuditEvent — immutable record of a security-relevant action in the system.
 *
 * Key design decisions:
 *  1. No update/delete operations — audit logs are append-only for accountability.
 *  2. username is stored as a plain string (not FK) so the log is preserved even
 *     if the user account is later deleted.
 *  3. ipAddress is nullable — internal/programmatic events don't have one.
 *  4. details is a free-text field for additional context (e.g., "locked after 5 failed attempts").
 */
@Entity
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_username", columnList = "username"),
        @Index(name = "idx_audit_created_at", columnList = "createdAt")
})
@Getter @Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The username who performed or was subject to the action. */
    @Column(nullable = false)
    private String username;

    /** Type of event, e.g. LOGIN_SUCCESS, LOGIN_FAILURE, REGISTER, LOGOUT, etc. */
    @Column(nullable = false)
    private String eventType;

    /** Client IP address — may be null for server-initiated events. */
    private String ipAddress;

    /** Optional human-readable extra context. */
    @Column(length = 512)
    private String details;

    /** When the event occurred. */
    @Column(nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
