package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * AdminService — user management operations (ADMIN only).
 *
 * Key learning points:
 *  1. createUser accepts a Set<String> of role names, resolves them from the DB, assigns all.
 *  2. assignRole / revokeRole modify the user's role set at runtime — no redeploy needed.
 *  3. UserSummary now returns Set<String> roles instead of a single enum value.
 */
@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;

    /** Create a user and assign the requested roles by name. */
    @Transactional
    public AuthResponse createUser(AdminRegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username '" + request.getUsername() + "' is already taken");
        }

        Set<Role> resolvedRoles = resolveRoles(request.getRoles());

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(resolvedRoles)
                .build();

        userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        Set<String> roleNames = resolvedRoles.stream().map(Role::getName).collect(Collectors.toSet());

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roleNames);

        return AuthResponse.builder()
                .accessToken(jwtUtil.generateToken(claims, userDetails))
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationMs())
                .username(user.getUsername())
                .roles(roleNames)
                .build();
    }

    /** Return all users (password-safe projection). */
    public List<UserSummary> getAllUsers() {
        return userRepository.findAll().stream().map(UserSummary::from).toList();
    }

    /** Return a single user by id. */
    public UserSummary getUserById(Long id) {
        return userRepository.findById(id)
                .map(UserSummary::from)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }

    /**
     * Assign an additional role to a user.
     * Idempotent — assigning a role the user already has is a no-op.
     */
    @Transactional
    public UserSummary assignRole(Long userId, AssignRoleRequest request) {
        User user = findUser(userId);
        Role role = findRole(request.getRoleName());
        user.getRoles().add(role);
        return UserSummary.from(userRepository.save(user));
    }

    /**
     * Revoke a role from a user.
     * Throws if the role is not currently assigned.
     */
    @Transactional
    public UserSummary revokeRole(Long userId, AssignRoleRequest request) {
        User user = findUser(userId);
        Role role = findRole(request.getRoleName());
        if (!user.getRoles().remove(role)) {
            throw new IllegalArgumentException(
                    "User '" + user.getUsername() + "' does not have role '" + request.getRoleName() + "'");
        }
        return UserSummary.from(userRepository.save(user));
    }

    /** Delete a user by id. Removes associated refresh token first to satisfy the FK. */
    @Transactional
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
        // Delete refresh token first (FK child before parent)
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);
        userRepository.delete(user);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private Set<Role> resolveRoles(Set<String> roleNames) {
        return roleNames.stream()
                .map(name -> roleRepository.findByName(name)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Role '" + name + "' does not exist — create it first via POST /api/admin/roles")))
                .collect(Collectors.toSet());
    }

    private User findUser(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }

    private Role findRole(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role '" + name + "' does not exist — create it first via POST /api/admin/roles"));
    }
}
