package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * UserController — endpoints accessible by ALL authenticated users (USER, MODERATOR, ADMIN).
 *
 * Role guard: @PreAuthorize("isAuthenticated()") — Spring Security already enforces
 * this via SecurityConfig, but the annotation makes intent explicit.
 */
@RestController
@RequestMapping("/api/user")
@PreAuthorize("isAuthenticated()")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    /**
     * GET /api/user/me
     * Returns the calling user's own profile (no password).
     */
    @GetMapping("/me")
    public ResponseEntity<UserSummary> getMyProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow();

        return ResponseEntity.ok(UserSummary.from(user));
    }

    /**
     * GET /api/user/dashboard
     * A resource every authenticated user can reach.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> userDashboard(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Welcome, " + userDetails.getUsername() + "!",
                "access", "USER level"
        ));
    }
}
