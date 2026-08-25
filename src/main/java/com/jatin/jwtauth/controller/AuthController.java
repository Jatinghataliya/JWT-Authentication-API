package com.jatin.jwtauth.controller;

import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.dto.ForgotPasswordRequest;
import com.jatin.jwtauth.dto.RefreshTokenRequest;
import com.jatin.jwtauth.dto.ResetPasswordRequest;
import com.jatin.jwtauth.service.AuthService;
import com.jatin.jwtauth.service.EmailVerificationService;
import com.jatin.jwtauth.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "1. Authentication", description = "Register, login, refresh token, and logout. No token required for register/login.")
@SecurityRequirements   // override global security — register/login are public
public class AuthController {

    private final AuthService authService;
    private final EmailVerificationService emailVerificationService;
    private final PasswordResetService passwordResetService;

    @Operation(summary = "Register a new user",
               description = "Creates a new account with the USER role and returns an access + refresh token pair immediately.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Registered successfully — tokens returned",
                     content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Username already taken or validation failed",
                     content = @Content)
    })
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @Operation(summary = "Login",
               description = "Authenticate with existing credentials and receive an access + refresh token pair.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Login successful — tokens returned",
                     content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid username or incorrect credential",
                     content = @Content)
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody AuthRequest request,
            jakarta.servlet.http.HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();
        return ResponseEntity.ok(authService.login(request, ip));
    }

    @Operation(summary = "Refresh access token",
               description = "Exchange a valid refresh token for a new short-lived access token. No Bearer header needed.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "New access token issued",
                     content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Refresh token missing, not found, or expired",
                     content = @Content)
    })
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshAccessToken(request.getRefreshToken()));
    }

    @Operation(summary = "Verify email address",
               description = "Confirms the email address using the one-time token sent on registration. Token is consumed after first use.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Email verified successfully"),
        @ApiResponse(responseCode = "400", description = "Token unknown or already used", content = @Content)
    })
    @GetMapping("/verify")
    public ResponseEntity<java.util.Map<String, String>> verifyEmail(
            @org.springframework.web.bind.annotation.RequestParam String token) {
        emailVerificationService.verifyToken(token);
        return ResponseEntity.ok(java.util.Map.of("message", "Email verified successfully"));
    }

    @Operation(summary = "Resend verification email",
               description = "Generates a fresh token and re-sends the verification email. Requires a valid access token.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Verification email resent"),
        @ApiResponse(responseCode = "400", description = "No email on file or already verified", content = @Content)
    })
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(
            @AuthenticationPrincipal UserDetails userDetails) {
        emailVerificationService.resendVerification(userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Request a password reset email",
               description = "Sends a one-time reset link to the registered email address. Always returns 204 regardless of whether the email exists — prevents user enumeration.")
    @ApiResponse(responseCode = "204", description = "Reset email sent (or silently ignored if email unknown)")
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.requestReset(request.getEmail());
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Reset password using the one-time token",
               description = "Validates the reset token and sets a new password. The token is consumed after first use.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Password reset successfully"),
        @ApiResponse(responseCode = "400", description = "Token invalid, expired, or already used", content = @Content)
    })
    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Logout",
               description = "Blacklists the current access token (immediately revoked) and deletes the refresh token. Both tokens become invalid.")
    @ApiResponse(responseCode = "204", description = "Logged out — access token blacklisted, refresh token deleted")
    @SecurityRequirement(name = "bearerAuth")   // override class-level @SecurityRequirements — this one needs a token
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            jakarta.servlet.http.HttpServletRequest request) {
        // Extract the raw JWT from the Authorization header to blacklist its JTI
        String authHeader = request.getHeader("Authorization");
        String accessToken = authHeader.substring("Bearer ".length());
        authService.logout(accessToken, userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }
}
