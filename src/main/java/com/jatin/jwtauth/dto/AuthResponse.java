package com.jatin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String username;
    /** All roles assigned to this user, e.g. ["USER", "EDITOR"] */
    private Set<String> roles;
}
