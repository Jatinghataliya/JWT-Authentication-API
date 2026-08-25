package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuditEventSummary;
import com.jatin.jwtauth.dto.PagedResponse;
import com.jatin.jwtauth.entity.AuditEvent;
import com.jatin.jwtauth.repository.AuditEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
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

    /** Return up to 100 most recent events, optionally filtered by username (non-pageable legacy). */
    @Transactional(readOnly = true)
    public List<AuditEventSummary> getEvents(String username) {
        Pageable top100 = PageRequest.of(0, 100, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AuditEvent> page = (username != null && !username.isBlank())
                ? auditEventRepository.findByUsername(username, top100)
                : auditEventRepository.findAll(top100);

        return page.getContent().stream()
                .map(this::toSummary)
                .collect(Collectors.toList());
    }

    /** Return paginated events, optionally filtered by username. */
    @Transactional(readOnly = true)
    public PagedResponse<AuditEventSummary> getEventsPaged(String username, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AuditEvent> result = (username != null && !username.isBlank())
                ? auditEventRepository.findByUsername(username, pageable)
                : auditEventRepository.findAll(pageable);

        List<AuditEventSummary> content = result.getContent().stream()
                .map(this::toSummary)
                .collect(Collectors.toList());

        return new PagedResponse<>(content, result.getNumber(), result.getSize(),
                result.getTotalElements(), result.getTotalPages(), result.isLast());
    }

    private AuditEventSummary toSummary(AuditEvent e) {
        return new AuditEventSummary(e.getId(), e.getUsername(), e.getEventType(),
                e.getIpAddress(), e.getDetails(), e.getCreatedAt());
    }
}
