package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/moderator")
@PreAuthorize("hasAnyRole('MODERATOR', 'ADMIN')")
@RequiredArgsConstructor
@Tag(name = "3. Moderator", description = "Read-only user management. Requires MODERATOR or ADMIN role.")
@SecurityRequirement(name = "bearerAuth")
public class ModeratorController {

    private final UserRepository userRepository;

    @Operation(summary = "Moderator dashboard")
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> moderatorDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Moderator Dashboard",
                "access", "MODERATOR level"
        ));
    }

    @Operation(summary = "List all users", description = "Returns all registered users. No passwords included.")
    @GetMapping("/users")
    public ResponseEntity<List<UserSummary>> listUsers() {
        return ResponseEntity.ok(
                userRepository.findAll().stream().map(UserSummary::from).toList());
    }

    @Operation(summary = "Get user by ID")
    @GetMapping("/users/{id}")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(UserSummary::from)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }
}
