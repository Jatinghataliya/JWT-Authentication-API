package com.jatin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * AuditEventSummary — read-only projection returned from GET /api/admin/audit.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuditEventSummary {
    private Long id;
    private String username;
    private String eventType;
    private String ipAddress;
    private String details;
    private Instant createdAt;
}
