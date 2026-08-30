package com.jatin.jwtauth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * PasswordPolicyConfig — centralised, hot-reloadable password rules.
 *
 * Bound from the "app.password-policy.*" namespace in application.yml.
 * Defaults are intentionally lenient so existing tests keep passing;
 * tighten via env vars or the admin PUT /api/admin/settings/password-policy.
 *
 * Key learning point:
 *  @ConfigurationProperties + @Component lets us bind a whole YAML subtree
 *  to a plain Java bean and inject it anywhere via @Autowired / constructor.
 */
@Component
@ConfigurationProperties(prefix = "app.password-policy")
@Getter
@Setter
public class PasswordPolicyConfig {

    /** Minimum password length (default 6 — keeps legacy registrations valid). */
    private int minLength = 6;

    /** Require at least one uppercase letter (A–Z). */
    private boolean requireUppercase = false;

    /** Require at least one digit (0–9). */
    private boolean requireDigit = false;

    /** Require at least one special character (!@#$%^&* …). */
    private boolean requireSpecialChar = false;

    /**
     * Days after which a password is considered expired.
     * 0 = never expire (default — no disruption to existing users).
     */
    private int expiryDays = 0;
}
