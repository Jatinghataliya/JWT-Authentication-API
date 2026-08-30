package com.jatin.jwtauth.validation;

import com.jatin.jwtauth.config.PasswordPolicyConfig;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * PasswordStrengthValidator — enforces runtime-configurable password rules.
 *
 * Rules are read from {@link PasswordPolicyConfig} on every validation call,
 * so they take effect without a restart when changed via the admin API.
 *
 * Checks performed (each independently configurable):
 *  1. Minimum length        — always enforced (default 6)
 *  2. At least one uppercase — when requireUppercase=true
 *  3. At least one digit     — when requireDigit=true
 *  4. At least one special   — when requireSpecialChar=true
 *
 * Key learning point:
 *  ConstraintValidator is a Spring bean here (@Component) so we can inject
 *  PasswordPolicyConfig directly. Without @Component, Hibernate Validator
 *  would instantiate it without Spring's DI — we'd have to use the
 *  ConstraintValidatorFactory bridge, which is more complex.
 */
@Component
@RequiredArgsConstructor
public class PasswordStrengthValidator implements ConstraintValidator<PasswordStrength, String> {

    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    private final PasswordPolicyConfig policy;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext ctx) {
        // null is handled by @NotBlank — skip here to avoid double error messages
        if (password == null) return true;

        ctx.disableDefaultConstraintViolation();

        if (password.length() < policy.getMinLength()) {
            ctx.buildConstraintViolationWithTemplate(
                    "Password must be at least " + policy.getMinLength() + " characters"
            ).addConstraintViolation();
            return false;
        }

        if (policy.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase)) {
            ctx.buildConstraintViolationWithTemplate(
                    "Password must contain at least one uppercase letter"
            ).addConstraintViolation();
            return false;
        }

        if (policy.isRequireDigit() && password.chars().noneMatch(Character::isDigit)) {
            ctx.buildConstraintViolationWithTemplate(
                    "Password must contain at least one digit"
            ).addConstraintViolation();
            return false;
        }

        if (policy.isRequireSpecialChar() &&
                password.chars().noneMatch(c -> SPECIAL_CHARS.indexOf(c) >= 0)) {
            ctx.buildConstraintViolationWithTemplate(
                    "Password must contain at least one special character (!@#$%^&* …)"
            ).addConstraintViolation();
            return false;
        }

        return true;
    }
}
