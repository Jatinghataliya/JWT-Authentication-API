package com.jatin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** DTO for GET/PUT /api/admin/settings/password-policy. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordPolicyDto {

    /** Minimum password length. */
    private int minLength;

    /** Whether an uppercase letter is required. */
    private boolean requireUppercase;

    /** Whether a digit is required. */
    private boolean requireDigit;

    /** Whether a special character is required. */
    private boolean requireSpecialChar;

    /**
     * Password expiry in days. 0 = never expire.
     */
    private int expiryDays;
}
