package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {

    /** Returns true if the given JTI has been blacklisted. */
    boolean existsByJti(String jti);

    /**
     * Scheduled cleanup — delete all entries whose natural expiry has passed.
     * These tokens would be rejected by the JWT parser anyway (expired),
     * so keeping them wastes storage.
     */
    @Modifying
    @Query("DELETE FROM BlacklistedToken b WHERE b.expiresAt < :now")
    int deleteAllExpiredBefore(Instant now);
}
