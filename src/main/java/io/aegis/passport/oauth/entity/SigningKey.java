package io.aegis.passport.oauth.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * Persisted RSA key pair backing the OIDC JWKS endpoint. Stored so token
 * signatures survive restarts (the original generated a fresh key each boot,
 * invalidating live tokens).
 */
@Entity
@Table(name = "signing_keys")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_id", unique = true, nullable = false, length = 64)
    private String keyId;

    /** Base64-encoded X.509 public key. */
    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    /** Base64-encoded PKCS#8 private key. */
    @Column(name = "private_key", nullable = false, columnDefinition = "TEXT")
    private String privateKey;

    @Column(nullable = false)
    @Builder.Default
    private boolean active = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
