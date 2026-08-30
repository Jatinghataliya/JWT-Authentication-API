package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AssignRoleRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.PagedResponse;
import com.jatin.jwtauth.dto.UserSearchRequest;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RefreshTokenRepository;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.repository.UserSpecification;
import com.jatin.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.PrintWriter;
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
    private final AuditService auditService;

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
                .passwordChangedAt(java.time.LocalDateTime.now())
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

    /** Return all users (password-safe projection, non-pageable). Cached. */
    @Cacheable("users")
    public List<UserSummary> getAllUsers() {
        return userRepository.findAll().stream().map(UserSummary::from).toList();
    }

    /** Return paginated users sorted by username ascending by default. */
    public PagedResponse<UserSummary> getAllUsersPaged(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());
        Page<User> result = userRepository.findAll(pageable);
        List<UserSummary> content = result.getContent().stream()
                .map(UserSummary::from)
                .collect(Collectors.toList());
        return new PagedResponse<>(content, result.getNumber(), result.getSize(),
                result.getTotalElements(), result.getTotalPages(), result.isLast());
    }

    /**
     * Dynamic search with optional filters: username, email, role, enabled,
     * accountNonLocked, createdAfter, createdBefore.
     * All filters are ANDed; null/blank fields are ignored.
     */
    public PagedResponse<UserSummary> searchUsers(UserSearchRequest req) {
        Pageable pageable = PageRequest.of(
                req.getPage(), req.getSize(), Sort.by("username").ascending());
        Page<User> result = userRepository.findAll(
                UserSpecification.from(req), pageable);
        List<UserSummary> content = result.getContent().stream()
                .map(UserSummary::from)
                .collect(Collectors.toList());
        return new PagedResponse<>(content, result.getNumber(), result.getSize(),
                result.getTotalElements(), result.getTotalPages(), result.isLast());
    }

    /**
     * Write all users matching the search criteria to the given PrintWriter as CSV.
     * Uses streaming (no in-memory list of all rows) so large exports don't OOM.
     *
     * CSV columns:
     *   id, username, email, firstName, lastName, enabled, accountNonLocked,
     *   emailVerified, roles, createdAt
     */
    public void exportUsersCsv(UserSearchRequest req, PrintWriter writer) {
        // Fetch up to 10 000 rows for the export (safety cap)
        Pageable pageable = PageRequest.of(0, 10_000, Sort.by("username").ascending());
        Page<User> result = userRepository.findAll(
                UserSpecification.from(req), pageable);

        // Header
        writer.println("id,username,email,firstName,lastName,enabled,accountNonLocked,emailVerified,roles,createdAt");

        // Rows
        result.getContent().forEach(u -> {
            String roles = u.getRoles().stream()
                    .map(r -> r.getName())
                    .collect(Collectors.joining("|"));
            writer.printf("%d,%s,%s,%s,%s,%b,%b,%b,%s,%s%n",
                    u.getId(),
                    csvEscape(u.getUsername()),
                    csvEscape(u.getEmail()),
                    csvEscape(u.getFirstName()),
                    csvEscape(u.getLastName()),
                    u.isEnabled(),
                    u.isAccountNonLocked(),
                    u.isEmailVerified(),
                    csvEscape(roles),
                    u.getCreatedAt() != null ? u.getCreatedAt().toString() : ""
            );
        });
        writer.flush();
    }

    /** Wrap a value in double-quotes if it contains a comma, newline, or quote. */
    private static String csvEscape(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    /** Return a single user by id. Cached by id. */
    @Cacheable(value = "users", key = "#id")
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
    @CacheEvict(value = "users", allEntries = true)
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
    @CacheEvict(value = "users", allEntries = true)
    public UserSummary revokeRole(Long userId, AssignRoleRequest request) {
        User user = findUser(userId);
        Role role = findRole(request.getRoleName());
        if (!user.getRoles().remove(role)) {
            throw new IllegalArgumentException(
                    "User '" + user.getUsername() + "' does not have role '" + request.getRoleName() + "'");
        }
        return UserSummary.from(userRepository.save(user));
    }

    // ─── Account status management ────────────────────────────────────────────

    /**
     * Disable a user account. The user can no longer log in.
     * Any currently valid access tokens remain valid until they expire or are
     * blacklisted — this only prevents new logins.
     *
     * @throws IllegalArgumentException if trying to disable the last ADMIN
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public UserSummary disableUser(Long id) {
        User user = findUser(id);
        user.setEnabled(false);
        UserSummary result = UserSummary.from(userRepository.save(user));
        auditService.log(user.getUsername(), "ACCOUNT_DISABLED", "Account disabled by admin");
        return result;
    }

    /** Re-enable a previously disabled user account. */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public UserSummary enableUser(Long id) {
        User user = findUser(id);
        user.setEnabled(true);
        UserSummary result = UserSummary.from(userRepository.save(user));
        auditService.log(user.getUsername(), "ACCOUNT_ENABLED", "Account re-enabled by admin");
        return result;
    }

    /**
     * Lock a user account. Records the lock timestamp.
     * Locked users receive LockedException on login attempt.
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public UserSummary lockUser(Long id) {
        User user = findUser(id);
        user.setAccountNonLocked(false);
        user.setLockedAt(java.time.LocalDateTime.now());
        UserSummary result = UserSummary.from(userRepository.save(user));
        auditService.log(user.getUsername(), "ACCOUNT_LOCKED", "Account locked by admin");
        return result;
    }

    /** Unlock a previously locked user account and clear the lock timestamp. */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public UserSummary unlockUser(Long id) {
        User user = findUser(id);
        user.setAccountNonLocked(true);
        user.setLockedAt(null);
        UserSummary result = UserSummary.from(userRepository.save(user));
        auditService.log(user.getUsername(), "ACCOUNT_UNLOCKED", "Account unlocked by admin");
        return result;
    }

    /** Delete a user by id. Removes associated refresh token first to satisfy the FK. */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
        auditService.log(user.getUsername(), "ACCOUNT_DELETED", "Account deleted by admin");
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
