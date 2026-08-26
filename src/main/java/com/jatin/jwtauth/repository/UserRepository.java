package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByVerificationToken(String verificationToken);

    /**
     * Returns all users whose deletion was requested before the given cutoff
     * and who have not yet been erased (deletedAt is null).
     * Called by the scheduled erasure job to find accounts ready for PII wipe.
     */
    @Query("SELECT u FROM User u WHERE u.deletionRequestedAt IS NOT NULL " +
           "AND u.deletionRequestedAt < :cutoff AND u.deletedAt IS NULL")
    List<User> findAllPendingErasure(LocalDateTime cutoff);
}
