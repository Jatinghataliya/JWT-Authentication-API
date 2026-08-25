package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Safe user projection — never exposes the hashed password. */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserSummary {

    private Long id;
    private String username;
    private User.Role role;

    public static UserSummary from(User user) {
        return UserSummary.builder()
                .id(user.getId())
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }
}
