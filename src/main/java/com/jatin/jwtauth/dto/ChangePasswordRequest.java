package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.validation.PasswordStrength;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Request body for PUT /api/user/me/password. */
@Data
public class ChangePasswordRequest {

    @NotBlank(message = "Current password must not be blank")
    private String currentPassword;

    @NotBlank(message = "New password must not be blank")
    @PasswordStrength
    private String newPassword;
}
