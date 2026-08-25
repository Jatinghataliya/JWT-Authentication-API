package com.jatin.jwtauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Request body to create or update a role in the role catalog. */
@Data
public class RoleRequest {

    @NotBlank(message = "Role name must not be blank")
    @Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    private String name;

    private String description;
}
