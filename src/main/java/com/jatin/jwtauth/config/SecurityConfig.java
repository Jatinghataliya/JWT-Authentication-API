package com.jatin.jwtauth.config;

import com.jatin.jwtauth.filter.JwtAuthFilter;
import com.jatin.jwtauth.security.OAuth2SuccessHandler;
import com.jatin.jwtauth.service.OAuth2UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

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
    private final OAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    /** Comma-separated allowed origins — override via CORS_ORIGINS env var in production. */
    @Value("${app.cors.allowed-origins:http://localhost:5173,http://localhost:3000}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS using our CorsConfigurationSource bean
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // Disable CSRF — REST APIs use tokens, not browser cookies
            .csrf(AbstractHttpConfigurer::disable)

            // Define which endpoints are public vs protected
            // Layer 1 of RBAC: URL-level rules (Layer 2 is @PreAuthorize on each controller method)
            // With dynamic roles, fine-grained role checks live ONLY in @PreAuthorize.
            // URL rules here only enforce authentication and broad path-level ADMIN guard.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/resend-verification").authenticated() // requires token
                .requestMatchers("/api/auth/**").permitAll()               // public — login, register, refresh
                .requestMatchers("/login/oauth2/**", "/oauth2/**").permitAll() // OAuth2 callback URLs
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

            // STATELESS for API calls — but OAuth2 needs a brief session for the redirect flow
            // We use IF_REQUIRED so Spring can store the OAuth2 state parameter temporarily
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )

            // OAuth2 social login
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService)
                )
                .successHandler(oAuth2SuccessHandler)
                .failureHandler((request, response, exception) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401,\"error\":\"OAuth2 login failed\",\"message\":\""
                            + exception.getMessage() + "\"}");
                })
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

    /**
     * CORS configuration — allows the React admin panel (Vite dev :5173)
     * and any other origin listed in app.cors.allowed-origins to call the API.
     *
     * In production set: CORS_ORIGINS=https://admin.yourdomain.com
     * Never use * with allowCredentials(true).
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);   // required for HttpOnly cookie refresh token
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
