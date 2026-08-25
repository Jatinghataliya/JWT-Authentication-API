package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AdminRegisterRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.ChangeRoleRequest;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AdminService — operations only ADMIN can invoke.
 *
 * Key learning points:
 *  1. Admins can create users with any role (USER / MODERATOR / ADMIN).
 *  2. Admins can list all users, change a user's role, or delete a user.
 *  3. Passwords are never returned in any response (UserSummary DTO).
 */
@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    /** Create a user with an explicitly chosen role. */
    public AuthResponse createUser(AdminRegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username '" + request.getUsername() + "' is already taken");
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole().name());

        return AuthResponse.builder()
                .accessToken(jwtUtil.generateToken(claims, userDetails))
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationMs())
                .username(user.getUsername())
                .role(user.getRole().name())
                .build();
    }

    /** Return all users (password-safe projection). */
    public List<UserSummary> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserSummary::from)
                .toList();
    }

    /** Return a single user by id. */
    public UserSummary getUserById(Long id) {
        return userRepository.findById(id)
                .map(UserSummary::from)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }

    /** Change a user's role. */
    public UserSummary changeRole(Long id, ChangeRoleRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        user.setRole(request.getRole());
        return UserSummary.from(userRepository.save(user));
    }

    /** Delete a user by id. */
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalArgumentException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
    }
}
