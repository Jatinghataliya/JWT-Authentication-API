package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.AuditEventSummary;
import com.jatin.jwtauth.dto.RoleRequest;
import com.jatin.jwtauth.dto.RoleResponse;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.service.AdminService;
import com.jatin.jwtauth.service.AuditService;
import com.jatin.jwtauth.service.LoginAttemptService;
import com.jatin.jwtauth.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
@Tag(name = "4. Admin", description = "Full administrative control. Requires ADMIN role.")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    private final AdminService adminService;
    private final RoleService roleService;
    private final LoginAttemptService loginAttemptService;
    private final AuditService auditService;

    // ═══ Role Catalog ════════════════════════════════════════════════════════

    @Operation(summary = "List all roles", description = "Returns every role in the system catalog.")
    @GetMapping("/roles")
    public ResponseEntity<List<RoleResponse>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @Operation(summary = "Get role by ID")
    @GetMapping("/roles/{id}")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @Operation(summary = "Create a new role",
               description = "Creates a brand-new role at runtime — no code change or redeployment needed. Name is normalised to UPPER_CASE.")
    @PostMapping("/roles")
    public ResponseEntity<RoleResponse> createRole(@Valid @RequestBody RoleRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roleService.createRole(request));
    }

    @Operation(summary = "Update a role's description")
    @PutMapping("/roles/{id}")
    public ResponseEntity<RoleResponse> updateRole(@PathVariable Long id, @Valid @RequestBody RoleRequest request) {
        return ResponseEntity.ok(roleService.updateRole(id, request));
    }

    @Operation(summary = "Delete a role", description = "Removes the role from the catalog and all user assignments.")
    @DeleteMapping("/roles/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }

    // ═══ User Management ═════════════════════════════════════════════════════

    @Operation(summary = "Admin dashboard")
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> adminDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Admin Dashboard",
                "access", "ADMIN level — full control"
        ));
    }

    @Operation(summary = "Create user with specific roles",
               description = "Creates a user and assigns one or more roles by name. Roles must already exist in the catalog.")
    @PostMapping("/users")
    public ResponseEntity<AuthResponse> createUser(@Valid @RequestBody AdminRegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createUser(request));
    }

    @Operation(summary = "List all users", description = "Returns all registered users. No credentials included.")
    @GetMapping("/users")
    public ResponseEntity<List<UserSummary>> getAllUsers() {
        return ResponseEntity.ok(adminService.getAllUsers());
    }

    @Operation(summary = "Get user by ID")
    @GetMapping("/users/{id}")
    public ResponseEntity<UserSummary> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.getUserById(id));
    }

    @Operation(summary = "Assign a role to a user", description = "Idempotent — assigning an already-held role is a no-op.")
    @PostMapping("/users/{id}/roles")
    public ResponseEntity<UserSummary> assignRole(@PathVariable Long id, @Valid @RequestBody AssignRoleRequest request) {
        return ResponseEntity.ok(adminService.assignRole(id, request));
    }

    @Operation(summary = "Revoke a role from a user", description = "Returns 400 if the user does not hold the specified role.")
    @DeleteMapping("/users/{id}/roles")
    public ResponseEntity<UserSummary> revokeRole(@PathVariable Long id, @Valid @RequestBody AssignRoleRequest request) {
        return ResponseEntity.ok(adminService.revokeRole(id, request));
    }

    @Operation(summary = "Get recent login attempts for a user",
               description = "Returns the 20 most-recent login attempts (success and failure) for audit purposes.")
    @GetMapping("/users/{id}/login-attempts")
    public ResponseEntity<java.util.List<com.jatin.jwtauth.dto.LoginAttemptSummary>> getLoginAttempts(
            @PathVariable Long id) {
        String username = adminService.getUserById(id).getUsername();
        return ResponseEntity.ok(loginAttemptService.getRecentAttempts(username));
    }

    @Operation(summary = "Disable a user account",
               description = "Sets enabled=false. The user cannot log in until re-enabled. Existing valid access tokens are unaffected.")
    @PatchMapping("/users/{id}/disable")
    public ResponseEntity<UserSummary> disableUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.disableUser(id));
    }

    @Operation(summary = "Enable a user account",
               description = "Restores a previously disabled account. The user may log in immediately.")
    @PatchMapping("/users/{id}/enable")
    public ResponseEntity<UserSummary> enableUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.enableUser(id));
    }

    @Operation(summary = "Lock a user account",
               description = "Sets accountNonLocked=false and records lockedAt. Login attempts produce LockedException.")
    @PatchMapping("/users/{id}/lock")
    public ResponseEntity<UserSummary> lockUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.lockUser(id));
    }

    @Operation(summary = "Unlock a user account",
               description = "Clears the lock flag and lockedAt timestamp. The user may log in immediately.")
    @PatchMapping("/users/{id}/unlock")
    public ResponseEntity<UserSummary> unlockUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.unlockUser(id));
    }

    @Operation(summary = "Delete a user permanently")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    // ═══ Audit Log ═══════════════════════════════════════════════════════════

    @Operation(summary = "Query the security audit log",
               description = "Returns up to 100 most recent events. Optionally filter by username via ?username=xxx.")
    @GetMapping("/audit")
    public ResponseEntity<List<AuditEventSummary>> getAuditLog(
            @RequestParam(required = false) String username) {
        return ResponseEntity.ok(auditService.getEvents(username));
    }
}
