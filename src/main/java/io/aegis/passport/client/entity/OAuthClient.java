package io.aegis.passport.client.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
 * A registered OAuth2/OIDC client application. Adapts to Spring Authorization
 * Server's {@code RegisteredClient} at read time. Access can be restricted by
 * role codes and per-user allow/deny lists.
 */
@Entity
@Table(name = "oauth_clients", indexes = {
        @Index(name = "idx_client_client_id", columnList = "client_id")
})
@Getter
@Setter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", unique = true, nullable = false, length = 100)
    private String clientId;

    /** BCrypt-encoded secret. */
    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 100)
    private String clientName;

    @Column(name = "client_description", length = 500)
    private String clientDescription;

    @Column(name = "client_icon", length = 500)
    private String clientIcon;

    /** Comma-separated redirect URIs. */
    @Column(name = "redirect_uris", nullable = false, length = 1000)
    private String redirectUris;

    @Column(name = "grant_types", nullable = false, length = 500)
    @Builder.Default
    private String grantTypes = "authorization_code,refresh_token";

    @Column(nullable = false, length = 500)
    @Builder.Default
    private String scopes = "openid,profile,email";

    @Column(name = "access_token_ttl", nullable = false)
    @Builder.Default
    private Integer accessTokenTtl = 900;

    @Column(name = "refresh_token_ttl", nullable = false)
    @Builder.Default
    private Integer refreshTokenTtl = 604800;

    @Column(name = "authorization_code_ttl", nullable = false)
    @Builder.Default
    private Integer authorizationCodeTtl = 300;

    @Column(name = "require_pkce", nullable = false)
    @Builder.Default
    private boolean requirePkce = true;

    @Column(name = "require_consent", nullable = false)
    @Builder.Default
    private boolean requireConsent = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id")
    // owner -> roles -> permissions is a lazy graph; serializing it with
    // open-in-view disabled throws LazyInitializationException (500) on every
    // /api/clients response. The frontend doesn't display the owner, so drop it.
    @JsonIgnore
    private User owner;

    /** Comma-separated role codes allowed to use this client (empty = all). */
    @Column(name = "allowed_roles", length = 300)
    private String allowedRoles;

    /** Comma-separated user ids explicitly allowed (empty = no whitelist). */
    @Column(name = "allowed_users", length = 1000)
    private String allowedUsers;

    /** Comma-separated user ids explicitly denied. */
    @Column(name = "denied_users", length = 1000)
    private String deniedUsers;
    /** Expiry epoch milliseconds by user ID; absent entries in allowedUsers are permanent. */
    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    @Column(name="allowed_user_expirations",columnDefinition="json")
    private java.util.Map<String,Long> allowedUserExpirations;
    @Column(name="organization_restricted",nullable=false) @Builder.Default
    private boolean organizationRestricted=false;
    @Column(name="allowed_organizations",length=1000) private String allowedOrganizations;
    @Column(name="denied_organizations",length=1000) private String deniedOrganizations;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
}
