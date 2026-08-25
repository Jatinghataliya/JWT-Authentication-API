package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** Return all events for a specific user, newest first. */
    List<AuditEvent> findByUsernameOrderByCreatedAtDesc(String username);

    /** Return the most recent N events across all users. */
    List<AuditEvent> findTop100ByOrderByCreatedAtDesc();
}
