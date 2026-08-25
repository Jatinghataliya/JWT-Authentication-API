package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.ChangePasswordRequest;
import com.jatin.jwtauth.dto.UpdateProfileRequest;
import com.jatin.jwtauth.dto.UserSummary;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * UserService — profile management for the currently authenticated user.
 *
 * Key learning points:
 *  1. updateProfile() is a partial update — only non-null fields from the
 *     request are applied. This lets clients send just the fields they want
 *     to change without overwriting everything else.
 *  2. changePassword() verifies the current (old) password before allowing
 *     the update — prevents token theft from being used to lock a user out.
 *  3. Email uniqueness is enforced at the DB level (unique = true) and also
 *     checked here to produce a clear 400 message rather than a DB error.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Partial profile update — only non-null fields in the request are applied.
     *
     * @throws IllegalArgumentException if the requested email is already taken by another user
     */
    @Transactional
    public UserSummary updateProfile(String username, UpdateProfileRequest request) {
        User user = findUser(username);

        if (request.getEmail() != null) {
            // Ensure no other user already owns this email
            userRepository.findByEmail(request.getEmail())
                    .filter(existing -> !existing.getId().equals(user.getId()))
                    .ifPresent(__ -> {
                        throw new IllegalArgumentException(
                                "Email '" + request.getEmail() + "' is already in use");
                    });
            user.setEmail(request.getEmail());
        }

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }

        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }

        return UserSummary.from(userRepository.save(user));
    }

    /**
     * Change the user's own password after verifying the current one.
     *
     * @throws IllegalArgumentException if the current password is wrong
     */
    @Transactional
    public void changePassword(String username, ChangePasswordRequest request) {
        User user = findUser(username);

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
}
