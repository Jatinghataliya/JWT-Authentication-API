package com.jatin.jwtauth.service;

import com.jatin.jwtauth.dto.RoleRequest;
import com.jatin.jwtauth.dto.RoleResponse;
import com.jatin.jwtauth.entity.Role;
import com.jatin.jwtauth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * RoleService — CRUD for the role catalog.
 *
 * Key learning point:
 *  An ADMIN can call POST /api/admin/roles to add "EDITOR" or "BILLING_ADMIN"
 *  at runtime. Spring Security will honour those role names immediately on the
 *  next login — no code change or redeployment needed.
 */
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;

    /** Return all roles in the catalog. */
    public List<RoleResponse> getAllRoles() {
        return roleRepository.findAll().stream().map(RoleResponse::from).toList();
    }

    /** Return a single role by id. */
    public RoleResponse getRoleById(Long id) {
        return roleRepository.findById(id)
                .map(RoleResponse::from)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with id: " + id));
    }

    /** Create a new role. Name is normalised to upper-case and stripped of whitespace. */
    public RoleResponse createRole(RoleRequest request) {
        String name = request.getName().trim().toUpperCase();
        if (roleRepository.existsByName(name)) {
            throw new IllegalArgumentException("Role '" + name + "' already exists");
        }
        Role role = Role.builder().name(name).description(request.getDescription()).build();
        return RoleResponse.from(roleRepository.save(role));
    }

    /** Update a role's description (name cannot be changed to avoid breaking existing assignments). */
    public RoleResponse updateRole(Long id, RoleRequest request) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with id: " + id));
        role.setDescription(request.getDescription());
        return RoleResponse.from(roleRepository.save(role));
    }

    /** Delete a role by id. Cascades removal from all user_roles join rows automatically. */
    public void deleteRole(Long id) {
        if (!roleRepository.existsById(id)) {
            throw new IllegalArgumentException("Role not found with id: " + id);
        }
        roleRepository.deleteById(id);
    }
}
