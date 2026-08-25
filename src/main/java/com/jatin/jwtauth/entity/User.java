package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

/**
 * User entity — now holds a dynamic Set<Role> instead of a hardcoded enum.
 *
 * Key learning point:
 *  The @ManyToMany relationship creates a "user_roles" join table in the DB.
 *  A user can have ZERO or more roles. Roles are independent DB records and
 *  can be created at runtime without a code change.
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
