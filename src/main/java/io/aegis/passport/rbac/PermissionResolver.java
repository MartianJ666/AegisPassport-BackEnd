package io.aegis.passport.rbac;

import io.aegis.passport.rbac.entity.Role;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Single source of truth for "what can this user actually do". Resolves the
 * union of permissions granted via {@link Role}s and via direct
 * {@code user_permissions} grants, and the set of role codes. Results are
 * cached per user (Redis) and evicted whenever the user's roles or grants
 * change — see {@link #evict(Long)}.
 *
 * <p>This replaces the original static {@code ROLE_PERMISSIONS} map: role→
 * permission mappings now live in the database and are fully runtime-editable.
 */
@Service
@RequiredArgsConstructor
public class PermissionResolver {

    private final UserRepository userRepository;
    private final UserPermissionRepository userPermissionRepository;

    /** All permission codes this user effectively holds (roles ∪ direct grants). */
    // Direct grants can expire between requests. A cached union outlives their
    // deadlines (indefinitely with memory cache, 30 minutes with Redis).
    @Transactional(readOnly = true)
    public Set<String> effectivePermissions(Long userId) {
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Set.of();
        }
        Set<String> codes = new HashSet<>();
        for (Role role : user.getRoles()) {
            role.getPermissions().forEach(p -> codes.add(p.getCode()));
        }
        codes.addAll(userPermissionRepository.findValidPermissionCodes(userId, Instant.now()));
        codes.removeIf(PermissionCatalog::isRetired);
        return codes;
    }

    /** The user's role codes, e.g. {@code {"admin","member"}}. */
    // Role changes must also take effect without a cache/transaction race.
    @Transactional(readOnly = true)
    public Set<String> roleCodes(Long userId) {
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Set.of();
        }
        return user.getRoles().stream().map(Role::getCode).collect(Collectors.toSet());
    }

    public boolean hasPermission(Long userId, String code) {
        return effectivePermissions(userId).contains(code);
    }

    public boolean hasAnyPermission(Long userId, String... codes) {
        Set<String> held = effectivePermissions(userId);
        for (String c : codes) {
            if (held.contains(c)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasAllPermissions(Long userId, String... codes) {
        Set<String> held = effectivePermissions(userId);
        for (String c : codes) {
            if (!held.contains(c)) {
                return false;
            }
        }
        return true;
    }

    public boolean hasAnyRole(Long userId, String... roleCodes) {
        Set<String> held = roleCodes(userId);
        for (String r : roleCodes) {
            if (held.contains(r)) {
                return true;
            }
        }
        return false;
    }

    /** Invalidate a single user's cached permissions and roles. */
    public void evict(Long userId) {
        // annotation-driven eviction
    }

    /** Invalidate every user's cache (used when a role's permissions change). */
    public void evictAll() {
        // annotation-driven eviction
    }
}
