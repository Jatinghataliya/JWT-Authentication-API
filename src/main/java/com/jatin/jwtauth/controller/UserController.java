package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("isAuthenticated()")
@RequiredArgsConstructor
@Tag(name = "2. User", description = "Endpoints accessible by all authenticated users (USER, MODERATOR, ADMIN).")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserRepository userRepository;

    @Operation(summary = "Get my profile", description = "Returns the calling user's own id, username and roles. No password is returned.")
    @GetMapping("/me")
    public ResponseEntity<UserSummary> getMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow();
        return ResponseEntity.ok(UserSummary.from(user));
    }

    @Operation(summary = "User dashboard", description = "A welcome message confirming the user is authenticated.")
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> userDashboard(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Welcome, " + userDetails.getUsername() + "!",
                "access", "USER level"
        ));
    }
}
