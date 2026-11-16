package io.aegis.passport.rbac.dto;

import io.aegis.passport.rbac.entity.Permission;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/** Request/response records for the RBAC API, grouped in one file. */
public final class RbacDtos {

    private RbacDtos() {
    }

    public record PermissionView(Long id, String code, String name, String description, String category) {
        public static PermissionView from(Permission p) {
            return new PermissionView(p.getId(), p.getCode(), p.getName(), p.getDescription(), p.getCategory());
        }
    }

    public record RoleView(Long id, String code, String name, String description, boolean builtin,
                           List<String> permissions, long userCount, Instant createdAt) {
        public static RoleView from(Role r, long userCount) {
            List<String> perms = r.getPermissions().stream()
                    .map(Permission::getCode).filter(code -> !PermissionCatalog.isRetired(code)).sorted().toList();
            return new RoleView(r.getId(), r.getCode(), r.getName(), r.getDescription(),
                    r.isBuiltin(), perms, userCount, r.getCreatedAt());
        }
    }

    public record RoleCreateRequest(
            @NotBlank @Pattern(regexp = "[a-z][a-z0-9_]{1,49}",
                    message = "编码需为小写字母开头的字母数字下划线") String code,
            @NotBlank @Size(max = 100) String name,
            @Size(max = 255) String description,
            Set<String> permissions) {
    }

    public record RoleUpdateRequest(
            @NotBlank @Size(max = 100) String name,
            @Size(max = 255) String description,
            Set<String> permissions) {
    }

    public record GrantPermissionRequest(
            @NotBlank String permissionCode,
            String scope,
            Instant expiresAt) {
    }

    /**
     * A single direct grant, surfaced so the admin UI can show which of a user's
     * effective permissions come from direct assignment (with their scope and
     * expiry) rather than from a role.
     */
    public record DirectGrantView(String code, String name, String category,
                                  String scope, Instant expiresAt, Instant createdAt,
                                  boolean expired) {
    }
}
