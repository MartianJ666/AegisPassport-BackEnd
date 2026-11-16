package io.aegis.passport.oauth;

import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.consent.OAuthConsentRepository;
import io.aegis.passport.consent.entity.OAuthConsent;
import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.user.UserRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Custom consent persistence that reads from our {@code oauth_consents} table
 * instead of an in-memory map or Spring's default JdbcOperationOAuth2AuthorizationConsentService.
 * Also re-validates user access rights on every consent lookup so revoked roles
 * are honoured without manual consent cleanup.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AegisOAuth2ConsentService implements OAuth2AuthorizationConsentService {

    /** How long an approved consent is remembered (3 days, mirrors ConsentService). */
    private static final long REMEMBER_SECONDS = 3 * 24 * 3600;

    private final OAuthConsentRepository consentRepo;
    private final OAuthClientRepository clientRepo;
    private final UserRepository userRepo;
    private final PermissionResolver permissionResolver;

    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent consent) {
        String clientId = resolveClientId(consent.getRegisteredClientId());
        String principalName = consent.getPrincipalName();
        if (clientId == null || principalName == null) {
            return;
        }
        Set<String> scopes = consent.getScopes();
        String joined = scopes == null ? "" : String.join(",", scopes);
        Instant expiresAt = Instant.now().plusSeconds(REMEMBER_SECONDS);
        OAuthConsent existing = consentRepo
                .findByClientIdAndPrincipalName(clientId, principalName).orElse(null);
        if (existing == null) {
            existing = OAuthConsent.builder()
                    .clientId(clientId).principalName(principalName)
                    .scopes(joined).remember(true).expiresAt(expiresAt).build();
        } else {
            existing.setScopes(joined);
            existing.setRemember(true);
            existing.setExpiresAt(expiresAt);
        }
        consentRepo.save(existing);
        log.debug("[Consent] saved scopes={} for client {} principal {}", joined, clientId, principalName);
    }

    @Override
    @Transactional
    public void remove(OAuth2AuthorizationConsent consent) {
        String clientId = resolveClientId(consent.getRegisteredClientId());
        consentRepo.deleteByClientIdAndPrincipalName(clientId, consent.getPrincipalName());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        String clientId = resolveClientId(registeredClientId);
        Optional<OAuthConsent> opt = consentRepo.findByClientIdAndPrincipalName(clientId, principalName);
        if (opt.isEmpty()) return null;

        OAuthConsent stored = opt.get();
        if (stored.isExpired()) {
            return null;
        }
        // Re-validate user still has access to this client.
        var userOpt = userRepo.findByUsername(principalName);
        if (userOpt.isEmpty()) {
            return null;
        }
        var client = clientRepo.findByClientId(clientId).orElse(null);
        if (!io.aegis.passport.client.ClientAccessPolicy.allowed(client, userOpt.get())) return null;
        // Build SAS consent object from our stored scopes.
        var builder = OAuth2AuthorizationConsent.withId(registeredClientId, principalName);
        if (stored.getScopes() != null) {
            for (String scope : stored.getScopes().split(",")) {
                if (!scope.isBlank()) builder.scope(scope.trim());
            }
        }
        return builder.build();
    }

    /** Translates the numeric DB PK that SAS uses as registeredClientId to our client_id string. */
    private String resolveClientId(String registeredClientId) {
        try {
            Long dbId = Long.parseLong(registeredClientId);
            return clientRepo.findById(dbId)
                    .map(c -> c.getClientId())
                    .orElse(registeredClientId);
        } catch (NumberFormatException e) {
            return registeredClientId;
        }
    }
}
