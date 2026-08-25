package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** Return events for a specific user, newest first (pageable). */
    Page<AuditEvent> findByUsername(String username, Pageable pageable);

    /** Return all events across all users (pageable). */
    Page<AuditEvent> findAll(Pageable pageable);

    /** Non-pageable convenience for the legacy list query used in tests. */
    List<AuditEvent> findTop100ByOrderByCreatedAtDesc();
}
