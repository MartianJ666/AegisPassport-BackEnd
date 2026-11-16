package io.aegis.passport.rbac;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.dto.RbacDtos.PermissionView;
import io.aegis.passport.rbac.dto.RbacDtos.RoleCreateRequest;
import io.aegis.passport.rbac.dto.RbacDtos.RoleUpdateRequest;
import io.aegis.passport.rbac.dto.RbacDtos.RoleView;
import io.aegis.passport.rbac.entity.Permission;
import io.aegis.passport.rbac.entity.Role;
import io.aegis.passport.user.UserRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runtime role management — the core RBAC improvement. Every mutation that
 * could change a user's effective permissions invalidates the resolver cache so
 * access decisions never go stale.
 */
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PermissionResolver permissionResolver;
    private final io.aegis.passport.client.OAuthClientRepository clients;

    @Transactional(readOnly = true)
    public List<RoleView> listRoles() {
        return roleRepository.findAll().stream()
                .map(r -> RoleView.from(r, userRepository.countByRoles_Code(r.getCode())))
                .sorted((a, b) -> Boolean.compare(b.builtin(), a.builtin()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<PermissionView> listPermissions() {
        return permissionRepository.findAll().stream()
                .filter(p -> !PermissionCatalog.isRetired(p.getCode()))
                .map(PermissionView::from)
                .sorted((a, b) -> a.code().compareTo(b.code()))
                .toList();
    }

    @Transactional
    public RoleView createRole(RoleCreateRequest req) {
        if (roleRepository.existsByCode(req.code())) {
            throw BusinessException.of(ErrorCode.ROLE_ALREADY_EXISTS);
        }
        Role role = Role.builder()
                .code(req.code())
                .name(req.name())
                .description(req.description())
                .builtin(false)
                .permissions(resolvePermissions(req.permissions()))
                .build();
        roleRepository.save(role);
        return RoleView.from(role, 0);
    }

    @Transactional
    public RoleView updateRole(Long id, RoleUpdateRequest req) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> BusinessException.of(ErrorCode.ROLE_NOT_FOUND));
        role.setName(req.name());
        role.setDescription(req.description());
        if (req.permissions() != null) {
            Set<Permission> permissions = resolvePermissions(req.permissions());
            // These hidden grants may still be used by the original Passport.
            role.getPermissions().stream().filter(p -> PermissionCatalog.isRetired(p.getCode()))
                    .forEach(permissions::add);
            role.setPermissions(permissions);
        }
        roleRepository.save(role);
        // Any user with this role may now have different permissions.
        permissionResolver.evictAll();
        return RoleView.from(role, userRepository.countByRoles_Code(role.getCode()));
    }

    @Transactional
    public void deleteRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> BusinessException.of(ErrorCode.ROLE_NOT_FOUND));
        if (role.isBuiltin()) {
            throw BusinessException.of(ErrorCode.ROLE_BUILTIN_IMMUTABLE);
        }
        if (userRepository.countByRoles_Code(role.getCode()) > 0)
            throw BusinessException.of(ErrorCode.CONFLICT, "此角色仍有成员使用，请先调整成员角色");
        if (clients.findAll().stream().anyMatch(c -> io.aegis.passport.client.ClientAccessPolicy.csv(c.getAllowedRoles()).contains(role.getCode())))
            throw BusinessException.of(ErrorCode.CONFLICT, "此角色仍被应用访问规则引用，请先调整应用规则");
        roleRepository.delete(role);
        permissionResolver.evictAll();
    }

    private Set<Permission> resolvePermissions(Set<String> codes) {
        if (codes == null || codes.isEmpty()) {
            return new HashSet<>();
        }
        if (codes.stream().anyMatch(PermissionCatalog::isRetired)) {
            throw BusinessException.of(ErrorCode.PERMISSION_NOT_FOUND);
        }
        Set<Permission> resolved = codes.stream()
                .map(code -> permissionRepository.findByCode(code)
                        .orElseThrow(() -> BusinessException.of(
                                ErrorCode.PERMISSION_NOT_FOUND, "未知权限：" + code)))
                .collect(Collectors.toSet());
        return new HashSet<>(resolved);
    }
}
