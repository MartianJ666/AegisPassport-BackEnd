package io.aegis.passport.consent;

import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.consent.entity.OAuthConsent;
import io.aegis.passport.user.UserRepository;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ConsentService {

    private final OAuthConsentRepository repo;
    private final OAuthClientRepository clientRepo;
    private final UserRepository userRepo;
    private final org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizations;

    @Transactional(readOnly = true)
    public List<ConsentView> listByUser(String username) {
        // Every enabled client, annotated with this user's authorization state.
        // Previously only non-expired consents were returned, so apps whose consent
        // had lapsed (or were never authorized) were missing from the page.
        java.util.Map<String, OAuthConsent> byClient = repo.findByPrincipalName(username).stream()
                .collect(java.util.stream.Collectors.toMap(OAuthConsent::getClientId, c -> c, (a, b) -> a));
        // An administrator can forbid an app to a specific user via the client's
        // denied-users list (UserAppAccessDialog → "禁止"). Such an app must not
        // appear on the user's own "authorized applications" page — same rule
        // AccountConfirmFilter applies to the OAuth flow.
        var user = userRepo.findByUsername(username).orElse(null);
        return clientRepo.findAllByOrderByCreatedAtDesc().stream()
                .filter(OAuthClient::isEnabled)
                .filter(c -> io.aegis.passport.client.ClientAccessPolicy.allowed(c, user))
                .map(c -> {
                    OAuthConsent consent = byClient.get(c.getClientId());
                    String status;
                    Long id = null;
                    String scopes = null;
                    boolean remember = false;
                    Instant grantedAt = null;
                    if (consent != null && !consent.isExpired()) {
                        status = "granted";
                        id = consent.getId();
                        scopes = consent.getScopes();
                        remember = consent.isRemember();
                        grantedAt = consent.getCreatedAt();
                    } else if (consent != null) {
                        status = "expired";
                    } else {
                        status = "none";
                    }
                    return new ConsentView(id, c.getClientId(), c.getClientName(),
                            c.getClientIcon(), scopes, remember, grantedAt, status);
                }).toList();
    }

    private static Set<String> deniedUids(String csv) {
        if (csv == null || csv.isBlank()) return Set.of();
        return Arrays.stream(csv.split(",")).map(String::trim)
                .filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    @Transactional
    public void save(String clientId, String username, List<String> scopes, boolean remember) {
        var client = clientRepo.findByClientId(clientId == null ? "" : clientId).orElse(null);
        var user = userRepo.findByUsername(username).orElse(null);
        if (!io.aegis.passport.client.ClientAccessPolicy.allowed(client, user))
            throw io.aegis.passport.common.exception.BusinessException.of(io.aegis.passport.common.exception.ErrorCode.FORBIDDEN);
        Set<String> registered = Arrays.stream(client.getScopes().split(",")).map(String::trim).collect(Collectors.toSet());
        if (scopes == null || scopes.isEmpty() || scopes.stream().anyMatch(s -> s == null || !registered.contains(s)))
            throw io.aegis.passport.common.exception.BusinessException.of(io.aegis.passport.common.exception.ErrorCode.BAD_REQUEST, "授权范围无效");
        OAuthConsent existing = repo.findByClientIdAndPrincipalName(clientId, username).orElse(null);
        if (existing == null) {
            existing = new OAuthConsent();
            existing.setClientId(clientId);
            existing.setPrincipalName(username);
        }
        existing.setScopes(String.join(",", scopes));
        existing.setRemember(remember);
        if (remember) existing.setExpiresAt(Instant.now().plusSeconds(3 * 24 * 3600));
        else existing.setExpiresAt(null);
        repo.save(existing);
    }

    @Transactional
    public void revoke(Long id, String username) {
        repo.findById(id).ifPresent(c -> {
            if (c.getPrincipalName().equals(username)) { revokeTokens(username, c.getClientId()); repo.delete(c); }
        });
    }

    @Transactional
    public void revokeByClient(String clientId, String username) {
        revokeTokens(username, clientId);
        repo.deleteByClientIdAndPrincipalName(clientId, username);
    }
    private void revokeTokens(String username, String clientId) {
        if (authorizations instanceof io.aegis.passport.oauth.AuditedOAuth2AuthorizationService audited) audited.revokeByPrincipal(username, clientId);
    }

    public record ConsentView(Long id, String clientId, String clientName, String clientIcon,
                               String scopes, boolean remember, Instant grantedAt,
                               String status) {}
}
