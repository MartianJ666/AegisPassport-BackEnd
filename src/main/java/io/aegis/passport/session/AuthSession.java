package io.aegis.passport.session;

import io.aegis.passport.user.entity.User;
import jakarta.persistence.*;
import java.time.Instant;
import lombok.*;

@Entity
@Table(name = "auth_sessions", indexes = {
        @Index(name = "idx_auth_sessions_user_active", columnList = "user_id,revoked_at,expires_at"),
        @Index(name = "idx_auth_sessions_last_seen", columnList = "last_seen_at")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class AuthSession {
    @Id @Column(length = 36) private String id;
    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id", nullable = false) private User user;
    @Column(name = "device_hash", nullable = false, length = 64) private String deviceHash;
    @Column(name = "device_label", nullable = false, length = 160) private String deviceLabel;
    @Column(name = "ip_address", length = 64) private String ipAddress;
    @Column(name = "user_agent", length = 500) private String userAgent;
    @Column(name = "auth_method", nullable = false, length = 32) private String authMethod;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "last_seen_at", nullable = false) private Instant lastSeenAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Column(name = "revoked_reason", length = 100) private String revokedReason;
    @Column(name = "revoked_by", length = 100) private String revokedBy;
    public boolean isActiveAt(Instant now) { return revokedAt == null && expiresAt.isAfter(now); }
}
