package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Used by ADMIN to register a user with an explicit role (USER / MODERATOR / ADMIN).
 * Regular /register always creates a USER — only admins can assign higher roles.
 */
@Data
public class AdminRegisterRequest {

    @NotBlank(message = "Username must not be blank")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Password must not be blank")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;

    @NotNull(message = "Role must not be null")
    private User.Role role;
}
