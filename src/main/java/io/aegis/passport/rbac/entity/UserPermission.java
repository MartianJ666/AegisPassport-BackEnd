package io.aegis.passport.rbac.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A permission granted directly to a user, on top of whatever their roles
 * provide. Supports an optional resource {@link #scope} and an optional
 * {@link #expiresAt} for time-boxed elevation.
 */
@Entity
@Table(name = "user_permissions",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_user_permission",
                columnNames = {"user_id", "permission_id"}))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "permission_id", nullable = false)
    private Long permissionId;

    /** {@code null}/{@code *} means all resources; otherwise a resource id. */
    @Column(length = 100)
    private String scope;

    /** {@code null} means the grant never expires. */
    private Instant expiresAt;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
}
