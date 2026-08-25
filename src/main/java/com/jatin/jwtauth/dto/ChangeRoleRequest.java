package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.User;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/** Used by ADMIN to change an existing user's role. */
@Data
public class ChangeRoleRequest {

    @NotNull(message = "Role must not be null")
    private User.Role role;
}
