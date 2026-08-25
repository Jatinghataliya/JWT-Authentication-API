package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuditEventSummary;
import com.jatin.jwtauth.entity.AuditEvent;
import com.jatin.jwtauth.repository.AuditEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * AuditService — append-only security event logger.
 *
 * Key learning points:
 *  1. log() runs in REQUIRES_NEW so a failed business transaction doesn't
 *     roll back the audit record — we always want to know what was attempted.
 *  2. The method is intentionally fire-and-forget; callers don't need the
 *     returned event (it's void).
 *  3. ipAddress is nullable — pass null for non-HTTP events.
 *  4. Queries always order by createdAt DESC so the most recent events appear first.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditEventRepository auditEventRepository;

    /**
     * Persist a single audit record.
     *
     * @param username  user involved in the event
     * @param eventType short event code (e.g. "LOGIN_SUCCESS")
     * @param ipAddress client IP or null
     * @param details   optional extra context
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String username, String eventType, String ipAddress, String details) {
        AuditEvent event = AuditEvent.builder()
                .username(username)
                .eventType(eventType)
                .ipAddress(ipAddress)
                .details(details)
                .build();
        auditEventRepository.save(event);
        log.debug("Audit [{}] user='{}' ip='{}' details='{}'", eventType, username, ipAddress, details);
    }

    /** Overload without IP for server-initiated events. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String username, String eventType, String details) {
        log(username, eventType, null, details);
    }

    /** Return up to 100 most recent events, optionally filtered by username. */
    @Transactional(readOnly = true)
    public List<AuditEventSummary> getEvents(String username) {
        List<AuditEvent> events = (username != null && !username.isBlank())
                ? auditEventRepository.findByUsernameOrderByCreatedAtDesc(username)
                : auditEventRepository.findTop100ByOrderByCreatedAtDesc();

        return events.stream()
                .map(e -> new AuditEventSummary(
                        e.getId(), e.getUsername(), e.getEventType(),
                        e.getIpAddress(), e.getDetails(), e.getCreatedAt()))
                .collect(Collectors.toList());
    }
}
