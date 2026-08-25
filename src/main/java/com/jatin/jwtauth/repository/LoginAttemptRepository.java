package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    /**
     * Count consecutive failed attempts for a username within a time window.
     * Used by the brute-force guard to decide whether to auto-lock.
     */
    @Query("SELECT COUNT(a) FROM LoginAttempt a " +
           "WHERE a.username = :username AND a.success = false AND a.attemptedAt >= :since")
    int countFailedSince(String username, LocalDateTime since);

    /**
     * Returns the N most-recent attempts for a username (for admin audit view).
     * Ordered newest-first.
     */
    List<LoginAttempt> findTop20ByUsernameOrderByAttemptedAtDesc(String username);

    /**
     * Scheduled cleanup — remove old attempts to keep the table small.
     * Attempts older than the retention window are no longer useful.
     */
    @Modifying
    @Query("DELETE FROM LoginAttempt a WHERE a.attemptedAt < :before")
    int deleteAllBefore(LocalDateTime before);
}
