package com.jatin.jwtauth.config;

import com.jatin.jwtauth.filter.RateLimitInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * WebConfig — registers HandlerInterceptors for specific URL patterns.
 *
 * The rate-limit interceptor is applied ONLY to POST /api/auth/login
 * so other auth endpoints (register, refresh, logout) are unaffected.
 */
@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final RateLimitInterceptor rateLimitInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/api/auth/login");
    }
}
