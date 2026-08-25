package com.jatin.jwtauth.dto;

import com.jatin.jwtauth.entity.LoginAttempt;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/** Read-only projection of a LoginAttempt — safe to return to admins. */
@Data
@Builder
public class LoginAttemptSummary {

    private Long id;
    private String username;
    private String ipAddress;
    private boolean success;
    private LocalDateTime attemptedAt;

    public static LoginAttemptSummary from(LoginAttempt a) {
        return LoginAttemptSummary.builder()
                .id(a.getId())
                .username(a.getUsername())
                .ipAddress(a.getIpAddress())
                .success(a.isSuccess())
                .attemptedAt(a.getAttemptedAt())
                .build();
    }
}
