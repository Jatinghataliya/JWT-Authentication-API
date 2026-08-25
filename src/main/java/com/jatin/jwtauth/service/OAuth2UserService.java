package com.jatin.jwtauth.service;

import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.RoleRepository;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OAuth2UserService — JIT (just-in-time) user provisioning for social login.
 *
 * Key learning points:
 *  1. When a user logs in via Google for the first time, we create a local User
 *     account in our DB using their email as username (email is unique in Google).
 *  2. The email field is used as username so downstream JWT generation works with
 *     our existing UserDetailsServiceImpl.
 *  3. Existing users are looked up by email — no duplicates are created.
 *  4. The OAuth2 provider name (e.g. "google") is stored in the User's details
 *     field so we know the identity came from a social provider.
 *  5. We still return a DefaultOAuth2User (Spring's type) because Spring Security's
 *     OAuth2 authentication machinery expects that; our OAuth2SuccessHandler
 *     then converts it to a JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditService auditService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId(); // e.g. "google"
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // Extract the user's email from the provider attributes
        String email = (String) attributes.get("email");
        if (email == null || email.isBlank()) {
            throw new OAuth2AuthenticationException("Email not found in OAuth2 attributes from provider: " + provider);
        }

        // JIT provisioning — create or look up the local user
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> provisionNewUser(email, provider, attributes));

        log.info("OAuth2 login: user '{}' authenticated via provider '{}'", email, provider);
        auditService.log(email, "OAUTH2_LOGIN", "Provider: " + provider);

        // Return a DefaultOAuth2User with our internal user info merged in
        return new DefaultOAuth2User(
                List.of(new OAuth2UserAuthority("ROLE_USER", attributes)),
                attributes,
                "email"
        );
    }

    private User provisionNewUser(String email, String provider, Map<String, Object> attributes) {
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Default role 'USER' not found"));

        String firstName = (String) attributes.getOrDefault("given_name", "");
        String lastName  = (String) attributes.getOrDefault("family_name", "");

        User newUser = User.builder()
                .username(email)                   // use email as username for OAuth2 users
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .password("")                      // no password — OAuth2 users can't do form login
                .emailVerified(true)               // provider has verified the email
                .roles(Set.of(userRole))
                .build();

        User saved = userRepository.save(newUser);
        auditService.log(email, "REGISTER", "OAuth2 JIT provisioning via " + provider);
        log.info("OAuth2: provisioned new user '{}' from provider '{}'", email, provider);
        return saved;
    }
}
