package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.RefreshToken;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import com.jatin.jwtauth.service.TokenBlacklistService;
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

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtUtil jwtUtil;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserDetailsService userDetailsService;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private AuthService authService;

    private AuthRequest authRequest;
    private Role userRole;
    private User savedUser;
    private UserDetails springUserDetails;
    private RefreshToken mockRefreshToken;

    @BeforeEach
    void setUp() {
        authRequest = new AuthRequest();
        authRequest.setUsername("jatin");
        authRequest.setPassword("secret123");

        userRole = Role.builder().id(1L).name("USER").build();

        savedUser = User.builder()
                .id(1L)
                .username("jatin")
                .password("$2a$10$hashedPassword")
                .roles(Set.of(userRole))
                .build();

        springUserDetails = new org.springframework.security.core.userdetails.User(
                "jatin",
                "$2a$10$hashedPassword",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockRefreshToken = RefreshToken.builder()
                .id(1L)
                .token("mock-refresh-uuid")
                .user(savedUser)
                .expiryDate(Instant.now().plusSeconds(604800))
                .build();
    }

    @Test
    @DisplayName("register: new username → saves user with USER role and returns access + refresh token")
    void register_newUsername_returnsAuthResponse() {
        when(userRepository.existsByUsername("jatin")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("secret123")).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(refreshTokenService.createRefreshToken("jatin")).thenReturn(mockRefreshToken);
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("mocked.jwt.token");
        when(jwtUtil.getExpirationMs()).thenReturn(900_000L);

        AuthResponse response = authService.register(authRequest);

        assertThat(response.getAccessToken()).isEqualTo("mocked.jwt.token");
        assertThat(response.getRefreshToken()).isEqualTo("mock-refresh-uuid");
        assertThat(response.getUsername()).isEqualTo("jatin");
        assertThat(response.getRoles()).containsExactly("USER");
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(900_000L);

        verify(userRepository).save(any(User.class));
        verify(passwordEncoder).encode("secret123");
        verify(refreshTokenService).createRefreshToken("jatin");
    }

    @Test
    @DisplayName("register: duplicate username → throws IllegalArgumentException")
    void register_duplicateUsername_throwsException() {
        when(userRepository.existsByUsername("jatin")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(authRequest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already taken");

        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("register: password is encoded before saving — never stored as plain text")
    void register_passwordIsEncoded() {
        when(userRepository.existsByUsername("jatin")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("secret123")).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(refreshTokenService.createRefreshToken("jatin")).thenReturn(mockRefreshToken);
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("token");
        when(jwtUtil.getExpirationMs()).thenReturn(900_000L);

        authService.register(authRequest);

        verify(userRepository).save(argThat(user ->
                user.getPassword().equals("$2a$10$hashedPassword") &&
                !user.getPassword().equals("secret123")
        ));
    }

    @Test
    @DisplayName("login: valid credentials → authenticates and returns access + refresh token with roles")
    void login_validCredentials_returnsAuthResponse() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(org.springframework.security.core.Authentication.class));
        when(userDetailsService.loadUserByUsername("jatin")).thenReturn(springUserDetails);
        when(userRepository.findByUsername("jatin")).thenReturn(Optional.of(savedUser));
        when(refreshTokenService.createRefreshToken("jatin")).thenReturn(mockRefreshToken);
        when(jwtUtil.generateToken(anyMap(), eq(springUserDetails))).thenReturn("mocked.jwt.token");
        when(jwtUtil.getExpirationMs()).thenReturn(900_000L);

        AuthResponse response = authService.login(authRequest);

        assertThat(response.getAccessToken()).isEqualTo("mocked.jwt.token");
        assertThat(response.getRefreshToken()).isEqualTo("mock-refresh-uuid");
        assertThat(response.getUsername()).isEqualTo("jatin");
        assertThat(response.getRoles()).containsExactly("USER");

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(refreshTokenService).createRefreshToken("jatin");
    }

    @Test
    @DisplayName("login: wrong credentials → BadCredentialsException propagated")
    void login_wrongCredentials_throwsBadCredentialsException() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(authRequest))
                .isInstanceOf(BadCredentialsException.class);

        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }
}
