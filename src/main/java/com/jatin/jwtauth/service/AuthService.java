package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.AuthRequest;
import com.jatin.jwtauth.dto.AuthResponse;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import com.jatin.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    /**
     * Register a new user.
     * - Check username is unique
     * - Hash the password with BCrypt
     * - Save to DB
     * - Return a JWT immediately (auto-login after register)
     */
    public AuthResponse register(AuthRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username '" + request.getUsername() + "' is already taken");
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(User.Role.USER)
                .build();

        userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        return buildAuthResponse(userDetails, user.getRole());
    }

    /**
     * Authenticate an existing user.
     * - AuthenticationManager validates credentials (throws on failure)
     * - Generate and return JWT
     */
    public AuthResponse login(AuthRequest request) {
        // This will throw BadCredentialsException if credentials are wrong
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();

        return buildAuthResponse(userDetails, user.getRole());
    }

    private AuthResponse buildAuthResponse(UserDetails userDetails, User.Role role) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", role.name());

        String token = jwtUtil.generateToken(extraClaims, userDetails);

        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationMs())
                .username(userDetails.getUsername())
                .role(role.name())
                .build();
    }
}
