package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.PasswordResetToken;
import com.jatin.jwtauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    void deleteByUser(User user);

    /** Purge all expired or already-used tokens — called by @Scheduled cleanup. */
    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiryDate < :now OR t.used = true")
    void deleteExpiredOrUsed(Instant now);
}
