package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * User entity — holds credentials, profile fields, and a dynamic Set<Role>.
 *
 * Key learning points:
 *  - @CreationTimestamp / @UpdateTimestamp are managed entirely by Hibernate;
 *    no code needs to set them manually.
 *  - Profile fields (email, firstName, lastName) are nullable — existing users
 *    have no data for them until they update their profile.
 *  - enabled / accountNonLocked are read by Spring Security via UserDetails.
 *    Setting enabled=false blocks ALL logins for that user immediately.
 *    Setting accountNonLocked=false triggers AccountLockedException on login.
 *  - The @ManyToMany relationship creates a "user_roles" join table in the DB.
 */
@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    @NotBlank
    private String username;

    @Column(nullable = false)
    @NotBlank
    private String password;

    // ─── Profile fields ───────────────────────────────────────────────────────

    @Email
    @Column(unique = true)
    private String email;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    // ─── Audit timestamps ─────────────────────────────────────────────────────

    /** Set once at INSERT — Hibernate manages this automatically. */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Updated on every UPDATE — Hibernate manages this automatically. */
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // ─── Email verification ───────────────────────────────────────────────────

    /**
     * Whether the user has verified their email address.
     * false until they click the link sent on registration.
     */
    @Builder.Default
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    /**
     * One-time UUID token sent in the verification email.
     * Cleared to null once the email is successfully verified.
     */
    @Column(name = "verification_token", unique = true)
    private String verificationToken;

    // ─── Account-status flags ─────────────────────────────────────────────────

    /**
     * Whether the account is active. false → Spring Security rejects login
     * with DisabledException ("User is disabled").
     */
    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * Whether the account is unlocked. false → Spring Security rejects login
     * with LockedException ("User account is locked").
     */
    @Builder.Default
    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    /**
     * Timestamp of when the account was locked — informational only.
     * Null when the account is not locked.
     */
    @Column(name = "locked_at")
    private LocalDateTime lockedAt;

    // ─── Password policy ──────────────────────────────────────────────────────

    /**
     * Timestamp of the last password change (set on register, changePassword, resetPassword).
     * Used by the password-expiry check in JwtAuthFilter.
     * Null for users created before this feature was introduced (treated as not expired).
     */
    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    // ─── GDPR / Account deletion ──────────────────────────────────────────────

    /**
     * Set when the user requests account deletion via DELETE /api/user/me.
     * The account is immediately disabled; PII is erased 30 days later by
     * the scheduled job unless an admin performs an immediate hard-erase.
     * Null while the account is active.
     */
    @Column(name = "deletion_requested_at")
    private LocalDateTime deletionRequestedAt;

    /**
     * Set once PII has been wiped (scheduled or admin-triggered hard-erase).
     * Email, firstName, lastName, and password are overwritten;
     * username becomes "deleted_{id}" so audit rows remain coherent.
     * Null while the account has not yet been erased.
     */
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    // ─── Roles ───────────────────────────────────────────────────────────────

    /**
     * ManyToMany — one user can have many roles, one role can belong to many users.
     * EAGER fetch ensures roles are always loaded with the user (needed by Spring Security).
     * CascadeType.MERGE allows saving role references without re-persisting roles.
     */
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE})
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
}
