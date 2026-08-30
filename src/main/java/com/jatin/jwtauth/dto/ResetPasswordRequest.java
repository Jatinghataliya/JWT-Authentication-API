package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.validation.PasswordStrength;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * ResetPasswordRequest — body for POST /api/auth/reset-password.
 * The user supplies the single-use token (from the email link) plus the new password.
 */
@Data
public class ResetPasswordRequest {

    @NotBlank(message = "Token is required")
    private String token;

    @NotBlank(message = "New password is required")
    @PasswordStrength
    private String newPassword;
}
