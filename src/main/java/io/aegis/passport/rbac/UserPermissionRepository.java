package io.aegis.passport.rbac;

import io.aegis.passport.rbac.entity.UserPermission;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserPermissionRepository extends JpaRepository<UserPermission, Long> {

    List<UserPermission> findByUserId(Long userId);

    Optional<UserPermission> findByUserIdAndPermissionId(Long userId, Long permissionId);

    void deleteByUserIdAndPermissionId(Long userId, Long permissionId);

    /** Non-expired direct permission codes for a user, resolved via subquery. */
    @Query("SELECT p.code FROM Permission p WHERE p.id IN "
            + "(SELECT up.permissionId FROM UserPermission up "
            + "WHERE up.userId = :userId AND (up.expiresAt IS NULL OR up.expiresAt > :now))")
    List<String> findValidPermissionCodes(@Param("userId") Long userId, @Param("now") Instant now);

    /**
     * All direct grants for a user paired with their permission definition, so the
     * admin UI can render scope/expiry alongside each grant. Ordered newest-first.
     */
    @Query("SELECT up, p FROM UserPermission up JOIN Permission p ON p.id = up.permissionId "
            + "WHERE up.userId = :userId ORDER BY up.createdAt DESC")
    List<Object[]> findGrantsWithPermission(@Param("userId") Long userId);
}
