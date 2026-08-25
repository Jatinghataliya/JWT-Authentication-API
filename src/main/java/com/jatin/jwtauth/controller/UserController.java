package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.ChangePasswordRequest;
import com.jatin.jwtauth.dto.UpdateProfileRequest;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("isAuthenticated()")
@RequiredArgsConstructor
@Tag(name = "2. User", description = "Endpoints accessible by all authenticated users (USER, MODERATOR, ADMIN).")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserRepository userRepository;
    private final UserService userService;

    @Operation(summary = "Get my profile",
               description = "Returns the calling user's id, username, email, name, timestamps, and roles. No password returned.")
    @ApiResponse(responseCode = "200", description = "Profile returned",
                 content = @Content(schema = @Schema(implementation = UserSummary.class)))
    @GetMapping("/me")
    public ResponseEntity<UserSummary> getMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow();
        return ResponseEntity.ok(UserSummary.from(user));
    }

    @Operation(summary = "Update my profile",
               description = "Partial update — only non-null fields are changed. Email must be unique across all users.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Profile updated",
                     content = @Content(schema = @Schema(implementation = UserSummary.class))),
        @ApiResponse(responseCode = "400", description = "Validation error or email already taken",
                     content = @Content)
    })
    @PutMapping("/me")
    public ResponseEntity<UserSummary> updateMyProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdateProfileRequest request) {
        return ResponseEntity.ok(userService.updateProfile(userDetails.getUsername(), request));
    }

    @Operation(summary = "Change my password",
               description = "Verifies the current password before applying the new one. Minimum 6 characters for the new password.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Password changed successfully"),
        @ApiResponse(responseCode = "400", description = "Current password wrong or new password too short",
                     content = @Content)
    })
    @PutMapping("/me/password")
    public ResponseEntity<Void> changeMyPassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(userDetails.getUsername(), request);
        return ResponseEntity.noContent().build();
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
