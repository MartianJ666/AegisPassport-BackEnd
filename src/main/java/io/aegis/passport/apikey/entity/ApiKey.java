package io.aegis.passport.apikey.entity;

import io.aegis.passport.user.entity.User;
import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * A machine credential (key + hashed secret) a user can create to call the
 * public verification API. Admins may disable any key independently of the
 * owner's own enable/disable toggle.
 */
@Entity
@Table(name = "api_keys", indexes = {
        @Index(name = "idx_apikey_key", columnList = "api_key")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_name", nullable = false, length = 100)
    private String name;

    @Column(name = "api_key", unique = true, nullable = false, length = 64)
    private String apiKey;

    /** BCrypt-hashed secret; the plaintext is shown to the user only once. */
    @com.fasterxml.jackson.annotation.JsonIgnore
    @Column(name = "api_secret", nullable = false)
    private String apiSecret;

    @Column(length = 500)
    private String scopes;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "admin_disabled", nullable = false)
    @Builder.Default
    private boolean adminDisabled = false;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "use_count", nullable = false)
    @Builder.Default
    private long useCount = 0L;

    @ManyToOne(fetch = FetchType.LAZY)
    @com.fasterxml.jackson.annotation.JsonIgnore
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
