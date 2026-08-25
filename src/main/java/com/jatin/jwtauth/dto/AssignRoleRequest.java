package com.jatin.jwtauth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Request body used by ADMIN to assign or revoke a role on a user. */
@Data
public class AssignRoleRequest {

    @NotBlank(message = "Role name must not be blank")
    private String roleName;
}
