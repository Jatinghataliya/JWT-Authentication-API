package com.jatin.jwtauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

/**
 * Used by ADMIN to register a user and assign one or more roles by name.
 * Regular /register always assigns only the default "USER" role.
 */
@Data
public class AdminRegisterRequest {

    @NotBlank(message = "Username must not be blank")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Credential must not be blank")
    @Size(min = 6, message = "Credential must be at least 6 characters")
    private String password;

    @NotEmpty(message = "At least one role name must be provided")
    private Set<String> roles;
}
