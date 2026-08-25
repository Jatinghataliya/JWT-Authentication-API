package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuditEventSummary;
import com.jatin.jwtauth.dto.PagedResponse;
import com.jatin.jwtauth.entity.AuditEvent;
import com.jatin.jwtauth.repository.AuditEventRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuditService — verifies that log() persists events with the
 * correct fields, getEvents() filters by username, and getEventsPaged() returns
 * a correctly assembled PagedResponse.
 */
@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock private AuditEventRepository auditEventRepository;

    @InjectMocks
    private AuditService auditService;

    // ─── log(username, eventType, ipAddress, details) ────────────────────────

    @Test
    @DisplayName("log: persists AuditEvent with all provided fields")
    void log_withIp_persistsEventWithCorrectFields() {
        auditService.log("jatin", "LOGIN_SUCCESS", "10.0.0.1", "via /api/auth/login");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository).save(captor.capture());

        AuditEvent saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo("jatin");
        assertThat(saved.getEventType()).isEqualTo("LOGIN_SUCCESS");
        assertThat(saved.getIpAddress()).isEqualTo("10.0.0.1");
        assertThat(saved.getDetails()).isEqualTo("via /api/auth/login");
    }

    // ─── log(username, eventType, details) — no-IP overload ─────────────────

    @Test
    @DisplayName("log (no-IP overload): persists event with null ipAddress")
    void log_noIp_persistsEventWithNullIp() {
        // The 3-arg overload calls this.log(username, eventType, null, details) directly
        // (same-object call bypasses proxy), so the repository is only invoked once.
        auditService.log("admin", "USER_LOCKED", "auto-locked after 3 failures");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository, times(1)).save(captor.capture());

        AuditEvent saved = captor.getValue();
        assertThat(saved.getIpAddress()).isNull();
        assertThat(saved.getEventType()).isEqualTo("USER_LOCKED");
    }

    // ─── getEvents — filtered by username ────────────────────────────────────

    @Test
    @DisplayName("getEvents: username filter delegates to findByUsername with pageable")
    void getEvents_withUsername_delegatesToFindByUsername() {
        AuditEvent event = AuditEvent.builder()
                .id(1L)
                .username("jatin")
                .eventType("LOGIN_FAILURE")
                .createdAt(Instant.now())
                .build();
        Page<AuditEvent> page = new PageImpl<>(List.of(event));

        when(auditEventRepository.findByUsername(eq("jatin"), any(Pageable.class))).thenReturn(page);

        List<AuditEventSummary> result = auditService.getEvents("jatin");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getUsername()).isEqualTo("jatin");
        assertThat(result.get(0).getEventType()).isEqualTo("LOGIN_FAILURE");
        verify(auditEventRepository, never()).findAll(any(Pageable.class));
    }

    // ─── getEventsPaged ───────────────────────────────────────────────────────

    @Test
    @DisplayName("getEventsPaged: null username → returns all events with correct pagination metadata")
    void getEventsPaged_nullUsername_returnsAllEventsWithPaginationMetadata() {
        AuditEvent e1 = AuditEvent.builder().id(1L).username("alice").eventType("REGISTER").createdAt(Instant.now()).build();
        AuditEvent e2 = AuditEvent.builder().id(2L).username("bob").eventType("LOGIN_SUCCESS").createdAt(Instant.now()).build();
        // PageImpl(content) constructor sets size = content.size(), not the requested page size.
        // Use the 3-arg constructor: PageImpl(content, pageable, total) to control metadata.
        Page<AuditEvent> page = new PageImpl<>(
                List.of(e1, e2),
                org.springframework.data.domain.PageRequest.of(0, 10),
                2L);

        when(auditEventRepository.findAll(any(Pageable.class))).thenReturn(page);

        PagedResponse<AuditEventSummary> response = auditService.getEventsPaged(null, 0, 10);

        assertThat(response.getContent()).hasSize(2);
        assertThat(response.getTotalElements()).isEqualTo(2);
        assertThat(response.getPage()).isEqualTo(0);
        assertThat(response.getSize()).isEqualTo(10);
    }
}
