package com.jatin.jwtauth.filter;

import com.jatin.jwtauth.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * RateLimitInterceptor — enforces per-IP rate limits on the login endpoint.
 *
 * Key learning points:
 *  1. Interceptors run after the request is matched but before the controller.
 *  2. We use the client IP as the bucket key so each IP gets independent quota.
 *  3. X-Forwarded-For is checked first so load-balancer setups work correctly.
 *  4. Returns HTTP 429 with a Retry-After header on exceeding the limit.
 *  5. This interceptor is registered only for POST /api/auth/login in WebConfig.
 */
@Component
@RequiredArgsConstructor
public class RateLimitInterceptor implements HandlerInterceptor {

    private final RateLimitService rateLimitService;

    @Override
    public boolean preHandle(HttpServletRequest request,
                              HttpServletResponse response,
                              Object handler) throws Exception {
        String clientIp = resolveClientIp(request);

        if (!rateLimitService.tryConsume(clientIp)) {
            response.setStatus(429); // 429 Too Many Requests
            response.setContentType("application/json");
            response.setHeader("Retry-After", "60"); // suggest retry after 60 seconds
            response.getWriter().write(
                    "{\"status\":429,\"error\":\"Too Many Requests\"," +
                    "\"message\":\"Rate limit exceeded — please try again later\"}");
            return false; // stop request processing
        }

        return true; // allow request
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // X-Forwarded-For may contain multiple IPs — take the first (client IP)
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
