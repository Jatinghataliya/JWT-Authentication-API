package com.jatin.jwtauth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Role — a named authority stored in the database.
 *
 * Key learning point:
 *  By storing roles in the DB (not a Java enum) an admin can create new roles
 *  at runtime (e.g. "EDITOR", "BILLING_ADMIN") without a code change or redeployment.
 *
 *  Spring Security reads the "name" field and prefixes it with "ROLE_" automatically
 *  when it is supplied as a GrantedAuthority.
 */
@Entity
@Table(name = "roles")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Stored WITHOUT the "ROLE_" prefix (e.g. "USER", "ADMIN", "EDITOR").
     * Spring Security prepends "ROLE_" when the authority is evaluated, so
     *   hasRole('ADMIN')  checks for the authority "ROLE_ADMIN".
     */
    @Column(nullable = false, unique = true)
    @NotBlank
    private String name;

    @Column
    private String description;
}
