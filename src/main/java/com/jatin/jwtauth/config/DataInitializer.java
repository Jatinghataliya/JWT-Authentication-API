package com.jatin.jwtauth.config;

import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * DataInitializer — seeds the three base roles and a default admin user
 * into the DB on every startup if they don't already exist.
 *
 * Default admin credentials:
 *   username : admin
 *   password : admin123
 *
 * Key learning point:
 *  ApplicationRunner runs AFTER the Spring context and DB schema are ready.
 *  This is safe to run on every startup because we check existsByName first.
 *  In production you would use Flyway/Liquibase migrations instead.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        seedRole("USER",      "Standard user — read-only access to own profile");
        seedRole("MODERATOR", "Can view all users");
        seedRole("ADMIN",     "Full administrative access");
        log.info("DataInitializer: base roles ready");

        seedAdminUser("admin", "admin123");
    }

    private void seedRole(String name, String description) {
        if (!roleRepository.existsByName(name)) {
            roleRepository.save(Role.builder().name(name).description(description).build());
            log.info("DataInitializer: created role '{}'", name);
        }
    }

    /**
     * Seeds a default admin user if no user with that username exists yet.
     * If the user already exists but is missing the ADMIN role, it is added.
     * Password is BCrypt-hashed — never stored as plain text.
     */
    private void seedAdminUser(String username, String rawPassword) {
        Role adminRole = roleRepository.findByName("ADMIN")
                .orElseThrow(() -> new IllegalStateException("ADMIN role not found after seeding"));
        Role userRole  = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("USER role not found after seeding"));

        userRepository.findByUsername(username).ifPresentOrElse(existing -> {
            // User exists — ensure ADMIN role is present
            if (existing.getRoles().stream().noneMatch(r -> r.getName().equals("ADMIN"))) {
                existing.getRoles().add(adminRole);
                userRepository.save(existing);
                log.info("DataInitializer: granted ADMIN role to existing user '{}'", username);
            }
        }, () -> {
            // User does not exist — create fresh
            User admin = User.builder()
                    .username(username)
                    .password(passwordEncoder.encode(rawPassword))
                    .email("admin@jwtauth.local")
                    .firstName("Admin")
                    .lastName("User")
                    .enabled(true)
                    .emailVerified(true)
                    .passwordChangedAt(java.time.LocalDateTime.now())
                    .roles(Set.of(adminRole, userRole))
                    .build();
            userRepository.save(admin);
            log.info("DataInitializer: default admin user '{}' created (password: {})", username, rawPassword);
        });
    }
}
