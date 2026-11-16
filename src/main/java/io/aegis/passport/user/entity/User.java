package io.aegis.passport.user.entity;
import io.aegis.passport.rbac.entity.Role;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor; import lombok.Builder; import lombok.Getter;
import lombok.NoArgsConstructor; import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp; import org.hibernate.annotations.UpdateTimestamp;
@Entity @Table(name = "users", indexes = {
    @Index(name = "idx_users_username", columnList = "username"),
    @Index(name = "idx_users_email", columnList = "email"),
    @Index(name = "idx_users_enabled", columnList = "enabled")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @Column(unique = true, nullable = false, length = 50) private String username;
    @Column(nullable = false) private String password;
    @Column(unique = true, length = 100) private String email;
    @Column(name = "email_verified", nullable = false) @Builder.Default private boolean emailVerified = false;
    @Column(length = 20) private String phone;
    @Column(length = 100) private String nickname;
    @Column(length = 255) private String avatar;
    @Column(name = "avatar_md5", length = 32) private String avatarMd5;
    @Column(length = 100) private String orgName;
    @Column(name="organization_id") private Long organizationId;
    @Column(nullable = false) @Builder.Default private boolean enabled = true;
    @Column(nullable = false) @Builder.Default private boolean locked = false;
    @Column(name = "primary_role", length = 50) @Builder.Default private String primaryRole = "user";
    @Column(name = "violation_count", nullable = false) @Builder.Default private int violationCount = 0;
    @Column(name = "banned_until") private Instant bannedUntil;
    @Column(name = "needs_setup", nullable = false) @Builder.Default private boolean needsSetup = false;
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default private Set<Role> roles = new HashSet<>();
    @CreationTimestamp @Column(nullable = false, updatable = false) private Instant createdAt;
    @UpdateTimestamp @Column(nullable = false) private Instant updatedAt;
    private Instant lastLoginAt;
    public boolean isBanned() { return bannedUntil != null && Instant.now().isBefore(bannedUntil); }
}
