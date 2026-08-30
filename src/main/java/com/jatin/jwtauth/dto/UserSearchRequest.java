package com.jatin.jwtauth.dto;

import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDateTime;

/**
 * UserSearchRequest — query parameters for GET /api/admin/users/search.
 *
 * All fields are optional (null = no filter for that field).
 * Multiple non-null fields are ANDed together.
 *
 * Key learning point:
 *  Spring MVC binds @RequestParam query params to this @ModelAttribute DTO.
 *  @DateTimeFormat tells Spring how to parse the ISO date-time strings.
 */
@Data
public class UserSearchRequest {

    /** Partial, case-insensitive match on username. */
    private String username;

    /** Partial, case-insensitive match on email. */
    private String email;

    /** Exact role name (e.g. "ADMIN", "USER"). */
    private String role;

    /** Filter by enabled status. null = both. */
    private Boolean enabled;

    /** Filter by accountNonLocked. null = both. */
    private Boolean accountNonLocked;

    /** Only return users created after this timestamp (inclusive). */
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime createdAfter;

    /** Only return users created before this timestamp (inclusive). */
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime createdBefore;

    /** Page number (zero-based). */
    private int page = 0;

    /** Page size. */
    private int size = 20;
}
