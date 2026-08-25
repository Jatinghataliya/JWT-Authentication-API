package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.RoleRequest;
import com.jatin.jwtauth.dto.RoleResponse;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.service.AdminService;
import com.jatin.jwtauth.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * AdminController — ADMIN-only operations.
 *
 * Role Catalog (via RoleService):
 *   POST   /api/admin/roles             — create a new role
 *   GET    /api/admin/roles             — list all roles
 *   GET    /api/admin/roles/{id}        — get one role
 *   PUT    /api/admin/roles/{id}        — update a role's description
 *   DELETE /api/admin/roles/{id}        — delete a role
 *
 * User Management (via AdminService):
 *   POST   /api/admin/users             — create user with specific roles
 *   GET    /api/admin/users             — list all users
 *   GET    /api/admin/users/{id}        — get user by id
 *   POST   /api/admin/users/{id}/roles  — assign a role to a user
 *   DELETE /api/admin/users/{id}/roles  — revoke a role from a user
 *   DELETE /api/admin/users/{id}        — delete a user
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;
    private final RoleService roleService;

    // ═══════════════════════════════════════════════════════════
    // Role Catalog
    // ═══════════════════════════════════════════════════════════

    /** GET /api/admin/roles — list every role in the system */
    @GetMapping("/roles")
    public ResponseEntity<List<RoleResponse>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    /** GET /api/admin/roles/{id} */
    @GetMapping("/roles/{id}")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    /**
     * POST /api/admin/roles — create a new dynamic role at runtime
     * Body: { "name": "EDITOR", "description": "Can edit articles" }
     */
    @PostMapping("/roles")
    public ResponseEntity<RoleResponse> createRole(@Valid @RequestBody RoleRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roleService.createRole(request));
    }

    /**
     * PUT /api/admin/roles/{id} — update a role's description
     * Body: { "name": "ignored", "description": "Updated description" }
     */
    @PutMapping("/roles/{id}")
    public ResponseEntity<RoleResponse> updateRole(
            @PathVariable Long id,
            @Valid @RequestBody RoleRequest request) {
        return ResponseEntity.ok(roleService.updateRole(id, request));
    }

    /** DELETE /api/admin/roles/{id} — remove a role from the system */
    @DeleteMapping("/roles/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }

    // ═══════════════════════════════════════════════════════════
    // User Management
    // ═══════════════════════════════════════════════════════════

    /** GET /api/admin/dashboard */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> adminDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Admin Dashboard",
                "access", "ADMIN level — full control"
        ));
    }

    /**
     * POST /api/admin/users — create a user with one or more roles
     * Body: { "username": "alice", "secret": "s3cur3!", "roles": ["EDITOR", "USER"] }
     */
    @PostMapping("/users")
    public ResponseEntity<AuthResponse> createUser(@Valid @RequestBody AdminRegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createUser(request));
    }

    /** GET /api/admin/users */
    @GetMapping("/users")
    public ResponseEntity<List<UserSummary>> getAllUsers() {
        return ResponseEntity.ok(adminService.getAllUsers());
    }

    /** GET /api/admin/users/{id} */
    @GetMapping("/users/{id}")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.getUserById(id));
    }

    /**
     * POST /api/admin/users/{id}/roles — assign a role to a user
     * Body: { "roleName": "EDITOR" }
     */
    @PostMapping("/users/{id}/roles")
    public ResponseEntity<UserSummary> assignRole(
            @PathVariable Long id,
            @Valid @RequestBody AssignRoleRequest request) {
        return ResponseEntity.ok(adminService.assignRole(id, request));
    }

    /**
     * DELETE /api/admin/users/{id}/roles — revoke a role from a user
     * Body: { "roleName": "EDITOR" }
     */
    @DeleteMapping("/users/{id}/roles")
    public ResponseEntity<UserSummary> revokeRole(
            @PathVariable Long id,
            @Valid @RequestBody AssignRoleRequest request) {
        return ResponseEntity.ok(adminService.revokeRole(id, request));
    }

    /** DELETE /api/admin/users/{id} */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
