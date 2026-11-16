package io.aegis.passport.external.entity;

import io.aegis.passport.user.entity.User;
import jakarta.persistence.*;
import java.time.Instant;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "external_identities", uniqueConstraints = @UniqueConstraint(
        name = "uk_external_identity_subject", columnNames = {"provider", "issuer", "provider_subject"}))
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class ExternalIdentity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "user_id", nullable = false) private User user;
    @Column(nullable = false, length = 40) private String provider;
    @Column(nullable = false, length = 255) private String issuer;
    @Column(name = "provider_subject", nullable = false, length = 255) private String providerSubject;
    @Column(name = "display_name", length = 100) private String displayName;
    @Column(length = 500) private String avatar;
    @CreationTimestamp @Column(name = "created_at", nullable = false, updatable = false) private Instant createdAt;
    @Column(name = "last_authenticated_at") private Instant lastAuthenticatedAt;
}
