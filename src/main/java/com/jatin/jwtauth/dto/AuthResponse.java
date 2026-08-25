package com.jatin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Returned on login/register/refresh.
 * Now includes a refreshToken field alongside the short-lived accessToken.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;
    private String username;
    /** All roles assigned to this user, e.g. ["USER", "EDITOR"] */
    private Set<String> roles;
}
