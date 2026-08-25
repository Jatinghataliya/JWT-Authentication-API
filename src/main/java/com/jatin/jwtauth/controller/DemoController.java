package com.jatin.jwtauth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * DemoController — shows how protected endpoints work.
 *
 * Key learning point:
 *  - /api/user/me  → any authenticated user can access
 *  - /api/admin/dashboard → only ADMIN role (via @PreAuthorize)
 *  - @AuthenticationPrincipal injects the currently authenticated UserDetails
 *    directly from the SecurityContext — no session involved.
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    /** GET /api/user/me — returns info about the currently authenticated user */
    @GetMapping("/user/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "username", userDetails.getUsername(),
                "authorities", userDetails.getAuthorities().toString(),
                "message", "You are authenticated!"
        ));
    }

    /** GET /api/admin/dashboard — only accessible with ROLE_ADMIN */
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> adminDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Welcome to the Admin Dashboard!",
                "status", "ADMIN access granted"
        ));
    }

    /** GET /api/user/greet — accessible by any authenticated user */
    @GetMapping("/user/greet")
    public ResponseEntity<Map<String, String>> greet(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Hello, " + userDetails.getUsername() + "! Your JWT is valid."
        ));
    }
}
