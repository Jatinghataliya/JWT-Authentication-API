package com.jatin.jwtauth.config;

import com.jatin.jwtauth.filter.JwtAuthFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig — Spring Security 6 configuration.
 *
 * Key learning points:
 *  1. STATELESS session — no HttpSession is ever created (key for horizontal scaling).
 *  2. CSRF disabled — not needed for stateless REST APIs (tokens are not cookies).
 *  3. Our JwtAuthFilter runs BEFORE UsernamePasswordAuthenticationFilter.
 *  4. BCrypt hashes passwords — never store plain text.
 *  5. @EnableMethodSecurity allows @PreAuthorize on controller methods.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF — REST APIs use tokens, not browser cookies
            .csrf(AbstractHttpConfigurer::disable)

            // Define which endpoints are public vs protected
            // Layer 1 of RBAC: URL-level rules (Layer 2 is @PreAuthorize on each controller method)
            // With dynamic roles, fine-grained role checks live ONLY in @PreAuthorize.
            // URL rules here only enforce authentication and broad path-level ADMIN guard.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/resend-verification").authenticated() // requires token
                .requestMatchers("/api/auth/**").permitAll()               // public — login, register, refresh
                .requestMatchers("/actuator/**").permitAll()               // public — all actuator endpoints
                .requestMatchers(                                          // public — Swagger UI + OpenAPI spec
                        "/swagger-ui.html",
                        "/swagger-ui/**",
                        "/api-docs",
                        "/api-docs/**"
                ).permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")         // ADMIN only — URL guard
                .requestMatchers("/api/moderator/**").hasAnyRole("MODERATOR", "ADMIN")
                .requestMatchers("/api/user/**").authenticated()
                .anyRequest().authenticated()
            )

            // STATELESS — no session, no cookies → horizontally scalable
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Return 401 (not 403) for unauthenticated requests
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Authentication required\"}");
                })
            )

            // Use our DaoAuthenticationProvider (BCrypt + UserDetailsService)
            .authenticationProvider(authenticationProvider())

            // Register our JWT filter before Spring's default username/password filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt automatically handles salt — safe against rainbow table attacks
        return new BCryptPasswordEncoder();
    }
}
