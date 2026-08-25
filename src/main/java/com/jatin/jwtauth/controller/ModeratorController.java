package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * ModeratorController — endpoints accessible by MODERATOR and ADMIN.
 *
 * Role guard: hasAnyRole('MODERATOR','ADMIN')
 *
 * Key learning point: MODERATOR can VIEW users but cannot modify them.
 * That power is reserved for ADMIN only (AdminController).
 */
@RestController
@RequestMapping("/api/moderator")
@PreAuthorize("hasAnyRole('MODERATOR', 'ADMIN')")
@RequiredArgsConstructor
public class ModeratorController {

    private final UserRepository userRepository;

    /**
     * GET /api/moderator/dashboard
     * Moderator landing page.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> moderatorDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Moderator Dashboard",
                "access", "MODERATOR level"
        ));
    }

    /**
     * GET /api/moderator/users
     * Moderators can list all users (read-only view).
     */
    @GetMapping("/users")
    public ResponseEntity<List<UserSummary>> listUsers() {
        List<UserSummary> users = userRepository.findAll()
                .stream()
                .map(UserSummary::from)
                .toList();
        return ResponseEntity.ok(users);
    }

    /**
     * GET /api/moderator/users/{id}
     * Moderators can view a specific user's profile.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(UserSummary::from)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }
}
