package io.aegis.passport.rbac;

import io.aegis.passport.rbac.PermissionCatalog.PermissionDef;
import io.aegis.passport.rbac.PermissionCatalog.RoleDef;
import io.aegis.passport.rbac.entity.Permission;
import io.aegis.passport.rbac.entity.Role;
import java.util.HashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds and reconciles the permission catalog and built-in roles from
 * {@link PermissionCatalog} on every startup. New permissions/roles added to
 * the catalog appear automatically; the {@code admin} role always gains any
 * newly-added permission so it stays fully privileged. Custom roles created via
 * the API are never touched.
 */
@Slf4j
@Component
@Order(10)
@RequiredArgsConstructor
public class RbacInitializer {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final PermissionResolver permissionResolver;

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void seed() {
        int newPerms = 0;
        for (PermissionDef def : PermissionCatalog.PERMISSIONS) {
            if (!permissionRepository.existsByCode(def.code())) {
                permissionRepository.save(Permission.builder()
                        .code(def.code()).name(def.name())
                        .description(def.description()).category(def.category())
                        .build());
                newPerms++;
            }
        }
        for (RoleDef def : PermissionCatalog.BUILTIN_ROLES) {
            Role role = roleRepository.findByCode(def.code()).orElse(null);
            Set<Permission> perms = resolve(def.permissions());
            if (role == null) {
                roleRepository.save(Role.builder()
                        .code(def.code()).name(def.name())
                        .description(def.description()).builtin(true)
                        .permissions(perms).build());
            } else if (role.isBuiltin()) {
                // Keep built-in role permissions aligned with the catalog.
                // Preserve retired grants for the original Passport without
                role.getPermissions().stream().filter(p -> PermissionCatalog.isRetired(p.getCode()))
                        .forEach(perms::add);
                role.setPermissions(perms);
                roleRepository.save(role);
            }
        }
        log.info("[RBAC] 权限目录已同步：新增权限 {} 项，内置角色 {} 个",
                newPerms, PermissionCatalog.BUILTIN_ROLES.size());
        // Freshly-seeded permissions may not be visible to cached principal
        // instances from a previous startup (e.g. Redis). Invalidate everything
        // so the next JWT filter execution picks up the latest catalog.
        permissionResolver.evictAll();
    }

    private Set<Permission> resolve(java.util.List<String> codes) {
        Set<Permission> set = new HashSet<>();
        for (String code : codes) {
            permissionRepository.findByCode(code).ifPresent(set::add);
        }
        return set;
    }
}
