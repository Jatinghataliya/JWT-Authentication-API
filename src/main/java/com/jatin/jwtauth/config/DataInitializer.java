package com.jatin.jwtauth.config;

import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * DataInitializer — seeds the three base roles into the DB on every startup
 * if they don't already exist.
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

    @Override
    public void run(ApplicationArguments args) {
        seedRole("USER",      "Standard user — read-only access to own profile");
        seedRole("MODERATOR", "Can view all users");
        seedRole("ADMIN",     "Full administrative access");
        log.info("DataInitializer: base roles ready");
    }

    private void seedRole(String name, String description) {
        if (!roleRepository.existsByName(name)) {
            roleRepository.save(Role.builder().name(name).description(description).build());
            log.info("DataInitializer: created role '{}'", name);
        }
    }
}
