package io.aegis.passport.rbac;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.rbac.dto.RbacDtos.*;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.dto.UserDtos.UserView;
import io.aegis.passport.user.entity.User;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;
    private final UserPermissionService userPermissionService;
    private final PermissionResolver permissionResolver;
    private final UserRepository userRepository;

    // ── Permission catalog (read-only) ─────────────────────────────────────

    @RequirePermission(PermissionCatalog.ROLE_READ)
    @GetMapping("/permissions")
    public ResponseEntity<ApiResult<List<PermissionView>>> listPermissions() {
        return ResponseEntity.ok(ApiResult.ok(roleService.listPermissions()));
    }

    // ── Role CRUD ──────────────────────────────────────────────────────────

    @RequirePermission(PermissionCatalog.ROLE_READ)
    @GetMapping("/roles")
    public ResponseEntity<ApiResult<List<RoleView>>> listRoles() {
        return ResponseEntity.ok(ApiResult.ok(roleService.listRoles()));
    }

    @RequirePermission(PermissionCatalog.ROLE_WRITE)
    @PostMapping("/roles")
    public ResponseEntity<ApiResult<RoleView>> createRole(@Valid @RequestBody RoleCreateRequest req) {
        return ResponseEntity.ok(ApiResult.ok(roleService.createRole(req)));
    }

    @RequirePermission(PermissionCatalog.ROLE_WRITE)
    @PutMapping("/roles/{id}")
    public ResponseEntity<ApiResult<RoleView>> updateRole(
            @PathVariable Long id, @Valid @RequestBody RoleUpdateRequest req) {
        return ResponseEntity.ok(ApiResult.ok(roleService.updateRole(id, req)));
    }

    @RequirePermission(PermissionCatalog.ROLE_DELETE)
    @DeleteMapping("/roles/{id}")
    public ResponseEntity<ApiResult<Void>> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.ok(ApiResult.ok());
    }

    // ── Role members ───────────────────────────────────────────────────────

    @RequirePermission(PermissionCatalog.ROLE_READ)
    @GetMapping("/roles/{role}/users")
    public ResponseEntity<ApiResult<List<UserView>>> getRoleUsers(@PathVariable String role) {
        List<UserView> users = userRepository.findByRoles_Code(role).stream()
                .map(UserView::from)
                .toList();
        return ResponseEntity.ok(ApiResult.ok(users));
    }

    // ── Direct permission grants ───────────────────────────────────────────

    @RequirePermission(PermissionCatalog.USER_WRITE)
    @PostMapping("/users/{userId}/permissions")
    public ResponseEntity<ApiResult<Void>> grantPermission(
            @PathVariable Long userId, @RequestBody GrantPermissionRequest req) {
        userPermissionService.grant(userId, req.permissionCode(), req.scope(), req.expiresAt());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @RequirePermission(PermissionCatalog.USER_WRITE)
    @DeleteMapping("/users/{userId}/permissions/{code}")
    public ResponseEntity<ApiResult<Void>> revokePermission(
            @PathVariable Long userId, @PathVariable String code) {
        userPermissionService.revoke(userId, code);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @RequirePermission(PermissionCatalog.USER_READ)
    @GetMapping("/users/{userId}/permissions")
    public ResponseEntity<ApiResult<Set<String>>> getUserPermissions(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResult.ok(permissionResolver.effectivePermissions(userId)));
    }

    /** Direct grants only (with scope/expiry), distinct from the effective union above. */
    @RequirePermission(PermissionCatalog.USER_READ)
    @GetMapping("/users/{userId}/direct-permissions")
    public ResponseEntity<ApiResult<List<DirectGrantView>>> getDirectGrants(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResult.ok(userPermissionService.listGrants(userId)));
    }
}
