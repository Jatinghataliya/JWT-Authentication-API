package com.jatin.jwtauth.repository;

import com.jatin.jwtauth.dto.UserSearchRequest;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import jakarta.persistence.criteria.*;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

/**
 * UserSpecification — builds a JPA Criteria API {@link Specification<User>}
 * from a {@link UserSearchRequest}.
 *
 * Key learning point:
 *  JPA Specifications let you compose dynamic WHERE clauses at runtime without
 *  writing raw JPQL or @Query strings for every combination of filters.
 *  Each field in the request contributes one Predicate; all are AND-ed together.
 *  Null fields are simply skipped, so partial searches work correctly.
 */
public class UserSpecification {

    private UserSpecification() {} // utility class — no instances

    /**
     * Build a Specification from the search request.
     * Every non-null field in the request adds a predicate.
     */
    public static Specification<User> from(UserSearchRequest req) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // username LIKE %value% (case-insensitive)
            if (req.getUsername() != null && !req.getUsername().isBlank()) {
                predicates.add(cb.like(
                        cb.lower(root.get("username")),
                        "%" + req.getUsername().toLowerCase() + "%"
                ));
            }

            // email LIKE %value% (case-insensitive)
            if (req.getEmail() != null && !req.getEmail().isBlank()) {
                predicates.add(cb.like(
                        cb.lower(root.get("email")),
                        "%" + req.getEmail().toLowerCase() + "%"
                ));
            }

            // enabled = true/false
            if (req.getEnabled() != null) {
                predicates.add(cb.equal(root.get("enabled"), req.getEnabled()));
            }

            // accountNonLocked = true/false
            if (req.getAccountNonLocked() != null) {
                predicates.add(cb.equal(root.get("accountNonLocked"), req.getAccountNonLocked()));
            }

            // createdAt >= createdAfter
            if (req.getCreatedAfter() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), req.getCreatedAfter()));
            }

            // createdAt <= createdBefore
            if (req.getCreatedBefore() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), req.getCreatedBefore()));
            }

            // role — join through the user_roles join table
            if (req.getRole() != null && !req.getRole().isBlank()) {
                Join<User, Role> roleJoin = root.join("roles", JoinType.INNER);
                predicates.add(cb.equal(roleJoin.get("name"), req.getRole().toUpperCase()));
                // Avoid duplicates when a user has multiple roles
                query.distinct(true);
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
