package com.jatin.jwtauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request body for PUT /api/user/me.
 * All fields are optional — only non-null values are applied (partial update).
 */
@Data
public class UpdateProfileRequest {

    @Email(message = "Must be a valid email address")
    private String email;

    @Size(max = 50, message = "First name must be at most 50 characters")
    private String firstName;

    @Size(max = 50, message = "Last name must be at most 50 characters")
    private String lastName;
}
