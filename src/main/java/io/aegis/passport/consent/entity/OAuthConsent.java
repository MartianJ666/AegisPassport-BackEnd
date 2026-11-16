package io.aegis.passport.consent.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A user's remembered authorization decision for a client. When
 * {@link #remember} is set the consent is reused (until {@link #expiresAt})
 * so the user isn't re-prompted on every authorization request.
 */
@Entity
@Table(name = "oauth_consents",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_client_principal",
                columnNames = {"client_id", "principal_name"}))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "principal_name", nullable = false, length = 100)
    private String principalName;

    /** Comma-separated granted scopes. */
    @Column(length = 1000)
    private String scopes;

    @Column(nullable = false)
    @Builder.Default
    private boolean remember = false;

    private Instant expiresAt;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }
}
