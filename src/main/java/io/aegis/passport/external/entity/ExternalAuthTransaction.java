package io.aegis.passport.external.entity;

import io.aegis.passport.user.entity.User;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "external_auth_transactions")
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class ExternalAuthTransaction {
    @Id @Column(length = 64) private String id;
    @Column(nullable = false, length = 40) private String provider;
    @Column(name = "state_hash", nullable = false, length = 64) private String stateHash;
    @Column(name = "browser_hash", nullable = false, length = 64) private String browserHash;
    @Column(name = "pkce_verifier", length = 255) private String pkceVerifier;
    @Column(length = 128) private String nonce;
    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id") private User user;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "consumed_at") private Instant consumedAt;
    @Column(nullable = false, length = 32) @Builder.Default private String intent = "LOGIN";
    @CreationTimestamp @Column(name = "created_at", nullable = false, updatable = false) private Instant createdAt;
}
