package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.ChangeRoleRequest;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * AdminController — endpoints accessible by ADMIN only.
 *
 * Role guard: @PreAuthorize("hasRole('ADMIN')") on every method.
 *
 * Capabilities:
 *  - Create users with any role (USER / MODERATOR / ADMIN)
 *  - List all users
 *  - View any user by id
 *  - Change a user's role
 *  - Delete a user
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    /**
     * GET /api/admin/dashboard
     * Admin landing page.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> adminDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Admin Dashboard",
                "access", "ADMIN level — full control"
        ));
    }

    /**
     * POST /api/admin/users
     * Create a user with an explicit role.
     * Body: { "username": "mod1", "credentials": "pass123", "role": "MODERATOR" }
     */
    @PostMapping("/users")
    public ResponseEntity<AuthResponse> createUser(@Valid @RequestBody AdminRegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createUser(request));
    }

    /**
     * GET /api/admin/users
     * List all registered users (no passwords returned).
     */
    @GetMapping("/users")
    public ResponseEntity<List<UserSummary>> getAllUsers() {
        return ResponseEntity.ok(adminService.getAllUsers());
    }

    /**
     * GET /api/admin/users/{id}
     * Get a specific user by id.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.getUserById(id));
    }

    /**
     * PATCH /api/admin/users/{id}/role
     * Change a user's role.
     * Body: { "role": "MODERATOR" }
     */
    @PatchMapping("/users/{id}/role")
    public ResponseEntity<UserSummary> changeRole(
            @PathVariable Long id,
            @Valid @RequestBody ChangeRoleRequest request) {
        return ResponseEntity.ok(adminService.changeRole(id, request));
    }

    /**
     * DELETE /api/admin/users/{id}
     * Delete a user by id.
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
