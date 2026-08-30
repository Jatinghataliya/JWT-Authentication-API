package com.jatin.jwtauth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * @PasswordStrength — custom Bean Validation constraint.
 *
 * Apply to any String field that represents a new password.
 * The actual rules are read from {@link com.jatin.jwtauth.config.PasswordPolicyConfig}
 * at validation time so they update without restart.
 *
 * Key learning point:
 *  Custom constraints need a @Constraint(validatedBy=…) pointing at the
 *  ConstraintValidator implementation. The annotation itself just carries
 *  the metadata (message, groups, payload) required by the Bean Validation spec.
 */
@Documented
@Constraint(validatedBy = PasswordStrengthValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordStrength {

    String message() default "Password does not meet complexity requirements";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
