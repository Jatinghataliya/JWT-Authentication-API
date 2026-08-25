package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.stream.Collectors;

/** Safe user projection — never exposes the hashed password. */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserSummary {

    private Long id;
    private String username;
    /** All role names assigned to this user. */
    private Set<String> roles;

    public static UserSummary from(User user) {
        return UserSummary.builder()
                .id(user.getId())
                .username(user.getUsername())
                .roles(user.getRoles().stream()
                        .map(r -> r.getName())
                        .collect(Collectors.toSet()))
                .build();
    }
}
