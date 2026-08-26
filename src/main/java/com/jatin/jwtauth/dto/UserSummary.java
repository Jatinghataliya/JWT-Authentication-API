package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

/** Safe user projection — never exposes the hashed password. */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserSummary {

    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    /** true once the user clicks the verification link sent on registration. */
    private boolean emailVerified;
    /** false → account is disabled; admin must re-enable before user can log in. */
    private boolean enabled;
    /** false → account is locked (e.g. by brute-force protection or admin action). */
    private boolean accountNonLocked;
    /** When the account was locked; null if not currently locked. */
    private LocalDateTime lockedAt;
    /** All role names assigned to this user. */
    private Set<String> roles;
    /** Non-null when the user has requested account deletion (pending 30-day erasure). */
    private LocalDateTime deletionRequestedAt;
    /** Non-null once the account PII has been fully erased. */
    private LocalDateTime deletedAt;

    public static UserSummary from(User user) {
        return UserSummary.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .emailVerified(user.isEmailVerified())
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .lockedAt(user.getLockedAt())
                .roles(user.getRoles().stream()
                        .map(r -> r.getName())
                        .collect(Collectors.toSet()))
                .deletionRequestedAt(user.getDeletionRequestedAt())
                .deletedAt(user.getDeletedAt())
                .build();
    }
}
