package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthService.
 *
 * All dependencies are mocked — no Spring context, no DB, very fast.
 * Tests cover: successful register, duplicate username, successful login,
 * and wrong credentials.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtUtil jwtUtil;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserDetailsService userDetailsService;

    @InjectMocks
    private AuthService authService;

    private AuthRequest authRequest;
    private User savedUser;
    private UserDetails springUserDetails;

    @BeforeEach
    void setUp() {
        authRequest = new AuthRequest();
        authRequest.setUsername("jatin");
        authRequest.setPassword("secret123");

        savedUser = User.builder()
                .id(1L)
                .username("jatin")
                .password("$2a$10$hashedPassword")
                .role(User.Role.USER)
                .build();

        springUserDetails = new org.springframework.security.core.userdetails.User(
                "jatin",
                "$2a$10$hashedPassword",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    // ─── register ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("register: new username → saves user and returns token")
    void register_newUsername_returnsAuthResponse() {
        when(userRepository.existsByUsername("jatin")).thenReturn(false);
        when(passwordEncoder.encode("secret123")).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("mocked.jwt.token");
        when(jwtUtil.getExpirationMs()).thenReturn(86_400_000L);

        AuthResponse response = authService.register(authRequest);

        assertThat(response.getAccessToken()).isEqualTo("mocked.jwt.token");
        assertThat(response.getUsername()).isEqualTo("jatin");
        assertThat(response.getRole()).isEqualTo("USER");
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(86_400_000L);

        verify(userRepository).save(any(User.class));
        verify(passwordEncoder).encode("secret123");
    }

    @Test
    @DisplayName("register: duplicate username → throws IllegalArgumentException")
    void register_duplicateUsername_throwsException() {
        when(userRepository.existsByUsername("jatin")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(authRequest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jatin")
                .hasMessageContaining("already taken");

        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("register: password is encoded before saving — never stored as plain text")
    void register_passwordIsEncoded() {
        when(userRepository.existsByUsername("jatin")).thenReturn(false);
        when(passwordEncoder.encode("secret123")).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("token");
        when(jwtUtil.getExpirationMs()).thenReturn(86_400_000L);

        authService.register(authRequest);

        // Capture the user that was saved and verify password was encoded
        verify(userRepository).save(argThat(user ->
                user.getPassword().equals("$2a$10$hashedPassword") &&
                !user.getPassword().equals("secret123")
        ));
    }

    // ─── login ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("login: valid credentials → authenticates and returns token")
    void login_validCredentials_returnsAuthResponse() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(org.springframework.security.core.Authentication.class));
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(userRepository.findByUsername("jatin")).thenReturn(Optional.of(savedUser));
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("mocked.jwt.token");
        when(jwtUtil.getExpirationMs()).thenReturn(86_400_000L);

        AuthResponse response = authService.login(authRequest);

        assertThat(response.getAccessToken()).isEqualTo("mocked.jwt.token");
        assertThat(response.getUsername()).isEqualTo("jatin");
        assertThat(response.getRole()).isEqualTo("USER");

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("login: wrong credentials → BadCredentialsException propagated")
    void login_wrongCredentials_throwsBadCredentialsException() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(authRequest))
                .isInstanceOf(BadCredentialsException.class);

        // Never reaches the DB after auth fails
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }
}
