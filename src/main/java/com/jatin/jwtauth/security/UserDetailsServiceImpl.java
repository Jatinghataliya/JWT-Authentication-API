package com.jatin.jwtauth.security;

import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.entity.User;
import com.jatin.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * UserDetailsServiceImpl — loads a User from the database by username.
 *
 * Key learning points (dynamic roles + account flags):
 *  1. We iterate the user's Set<Role> and map EACH role to a GrantedAuthority.
 *     Spring Security receives a collection so hasRole('ADMIN') AND
 *     hasRole('EDITOR') can both be true for the same user simultaneously.
 *  2. The 4-argument User constructor exposes enabled, accountNonExpired,
 *     accountNonLocked and credentialsNonExpired.  Spring Security reads these
 *     before every authentication attempt:
 *       enabled=false        → DisabledException  (HTTP 401)
 *       accountNonLocked=false → LockedException  (HTTP 401)
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found with username: " + username));

        // Map every Role in the user's set to a Spring Security GrantedAuthority
        // e.g. Role{name="ADMIN"} → SimpleGrantedAuthority("ROLE_ADMIN")
        Set<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toSet());

        // 4-argument constructor: (username, password, enabled, accountNonExpired,
        //                          credentialsNonExpired, accountNonLocked, authorities)
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true,                       // accountNonExpired — not tracked separately
                true,                       // credentialsNonExpired — not tracked separately
                user.isAccountNonLocked(),
                authorities
        );
    }
}
