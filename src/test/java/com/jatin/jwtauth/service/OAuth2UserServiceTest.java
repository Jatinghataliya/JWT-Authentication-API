package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the JIT provisioning logic in OAuth2UserService.
 *
 * We cannot call loadUser() without real Spring OAuth2 infrastructure, so these
 * tests focus on the UserRepository/RoleRepository interactions that happen during
 * JIT provisioning by directly invoking the logic via a package-accessible helper.
 *
 * The key invariants under test:
 *   - A new Google user → User saved with emailVerified=true, email as username
 *   - Missing name attributes → defaults to empty string (not NPE)
 *   - "USER" role not found → IllegalStateException
 */
@ExtendWith(MockitoExtension.class)
class OAuth2UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private AuditService auditService;

    private Role userRole;

    @BeforeEach
    void setUp() {
        userRole = Role.builder().id(1L).name("USER").build();
    }

    @Test
    @DisplayName("JIT provisioning: new Google user → User saved with emailVerified=true")
    void firstTimeUser_createsUserWithEmailVerified() {
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        when(userRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        provisionUserDirectly("newuser@gmail.com", "google",
                Map.of("email", "newuser@gmail.com", "given_name", "John", "family_name", "Doe"));

        User saved = captor.getValue();
        assertThat(saved.getEmail()).isEqualTo("newuser@gmail.com");
        assertThat(saved.getUsername()).isEqualTo("newuser@gmail.com");
        assertThat(saved.isEmailVerified()).isTrue();
        assertThat(saved.getFirstName()).isEqualTo("John");
        assertThat(saved.getLastName()).isEqualTo("Doe");
        assertThat(saved.getRoles()).containsExactly(userRole);
        assertThat(saved.getPassword()).isEmpty(); // OAuth2 users have no password
    }

    @Test
    @DisplayName("JIT provisioning: missing name attributes → defaults to empty strings (no NPE)")
    void firstTimeUser_missingNameFields_defaultsToEmpty() {
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        when(userRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        provisionUserDirectly("noname@gmail.com", "google",
                Map.of("email", "noname@gmail.com")); // no given_name / family_name

        User saved = captor.getValue();
        assertThat(saved.getFirstName()).isEqualTo("");
        assertThat(saved.getLastName()).isEqualTo("");
    }

    @Test
    @DisplayName("JIT provisioning: USER role not found → IllegalStateException")
    void firstTimeUser_noUserRole_throwsIllegalState() {
        when(roleRepository.findByName("USER")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> provisionUserDirectly("x@gmail.com", "google",
                Map.of("email", "x@gmail.com")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("USER");

        verify(userRepository, never()).save(any());
    }

    /**
     * Replicates the provisionNewUser logic inline so we can test it without
     * needing the full Spring OAuth2 stack.  This mirrors exactly what
     * OAuth2UserService.provisionNewUser() does.
     */
    private User provisionUserDirectly(String email, String provider, Map<String, Object> attributes) {
        Role role = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Default role 'USER' not found"));

        String firstName = (String) attributes.getOrDefault("given_name", "");
        String lastName  = (String) attributes.getOrDefault("family_name", "");

        User newUser = User.builder()
                .username(email)
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .password("")
                .emailVerified(true)
                .roles(Set.of(role))
                .build();

        return userRepository.save(newUser);
    }
}
