package io.aegis.passport.rbac;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.dto.RbacDtos.DirectGrantView;
import io.aegis.passport.rbac.entity.Permission;
import io.aegis.passport.rbac.entity.UserPermission;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Manages directly-granted extra permissions on top of role-derived ones. */
@Service
@RequiredArgsConstructor
public class UserPermissionService {

    private final UserPermissionRepository userPermissionRepository;
    private final PermissionRepository permissionRepository;
    private final PermissionResolver permissionResolver;

    /** Direct grants for a user, each tagged with scope, expiry and expired flag. */
    @Transactional(readOnly = true)
    public List<DirectGrantView> listGrants(Long userId) {
        Instant now = Instant.now();
        return userPermissionRepository.findGrantsWithPermission(userId).stream()
                .filter(row -> !PermissionCatalog.isRetired(((Permission) row[1]).getCode()))
                .map(row -> {
                    UserPermission up = (UserPermission) row[0];
                    Permission p = (Permission) row[1];
                    boolean expired = up.getExpiresAt() != null && up.getExpiresAt().isBefore(now);
                    return new DirectGrantView(p.getCode(), p.getName(), p.getCategory(),
                            up.getScope(), up.getExpiresAt(), up.getCreatedAt(), expired);
                })
                .toList();
    }

    @Transactional
    public void grant(Long userId, String permissionCode, String scope, Instant expiresAt) {
        if (PermissionCatalog.isRetired(permissionCode)) {
            throw BusinessException.of(ErrorCode.PERMISSION_NOT_FOUND);
        }
        Permission perm = permissionRepository.findByCode(permissionCode)
                .orElseThrow(() -> BusinessException.of(ErrorCode.PERMISSION_NOT_FOUND,
                        "未知权限：" + permissionCode));
        userPermissionRepository.findByUserIdAndPermissionId(userId, perm.getId())
                .ifPresentOrElse(
                        existing -> {
                            existing.setScope(scope);
                            existing.setExpiresAt(expiresAt);
                            userPermissionRepository.save(existing);
                        },
                        () -> userPermissionRepository.save(UserPermission.builder()
                                .userId(userId).permissionId(perm.getId())
                                .scope(scope).expiresAt(expiresAt).build())
                );
        permissionResolver.evict(userId);
    }

    @Transactional
    public void revoke(Long userId, String permissionCode) {
        if (PermissionCatalog.isRetired(permissionCode)) {
            throw BusinessException.of(ErrorCode.PERMISSION_NOT_FOUND);
        }
        permissionRepository.findByCode(permissionCode).ifPresent(perm ->
                userPermissionRepository.deleteByUserIdAndPermissionId(userId, perm.getId()));
        permissionResolver.evict(userId);
    }
}
