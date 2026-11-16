package io.aegis.passport.oauth;

import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.client.entity.OAuthClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Delegating {@link OAuth2AuthorizationService} that records an audit entry every
 * time an authorization code is issued — i.e. a user authorized a login to a
 * connected app. Covers both the consent-submission path and the silent re-login
 * path (existing consent). The underlying store remains the in-memory service.
 */
public class AuditedOAuth2AuthorizationService implements OAuth2AuthorizationService {


    private final OAuth2AuthorizationService delegate;
    private final AuditLogService auditLogService;
    private final OAuthClientRepository clientRepo;
    private final io.aegis.passport.user.UserRepository users;
    private final Map<String, OAuth2Authorization> tracked = new ConcurrentHashMap<>();
    private final Map<String, String> authorizationSessions = new ConcurrentHashMap<>();

    public AuditedOAuth2AuthorizationService(OAuth2AuthorizationService delegate,
                                             AuditLogService auditLogService,
                                             OAuthClientRepository clientRepo,
                                             io.aegis.passport.user.UserRepository users) {
        this.delegate = delegate;
        this.auditLogService = auditLogService;
        this.clientRepo = clientRepo;
        this.users = users;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        tracked.put(authorization.getId(), authorization);
        HttpServletRequest activeRequest = currentRequest();
        if (activeRequest != null && activeRequest.getAttribute("passport.session-id") instanceof String sid) {
            authorizationSessions.put(authorization.getId(), sid);
        }
        // A fresh (non-invalidated) authorization code with no access token yet is
        // the code-issuance moment. The later token exchange re-saves with the code
        // invalidated + an access token, which is not audited here.
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (codeToken != null && !codeToken.isInvalidated()
                && authorization.getToken(OAuth2AccessToken.class) == null) {
            auditCodeIssued(authorization);
        }
    }

    private void auditCodeIssued(OAuth2Authorization authorization) {
        try {
            String clientId = null;
            String clientName = null;
            try {
                Long dbId = Long.parseLong(authorization.getRegisteredClientId());
                OAuthClient c = clientRepo.findById(dbId).orElse(null);
                if (c != null) {
                    clientId = c.getClientId();
                    clientName = c.getClientName();
                }
            } catch (NumberFormatException ignored) {
                // registeredClientId is not a numeric DB id — fall through
            }
            HttpServletRequest req = currentRequest();
            String ip = req != null ? extractIp(req) : null;
            String path = req != null ? req.getRequestURI() : null;
            String ua = req != null ? req.getHeader("User-Agent") : null;
            StringBuilder desc = new StringBuilder("授权登录应用");
            if (clientName != null && !clientName.isBlank()) {
                desc.append("：").append(clientName);
            }
            if (clientId != null) {
                desc.append("(").append(clientId).append(")");
            }
            auditLogService.recordAsync("oauth", "AUTHORIZE", desc.toString(),
                    authorization.getPrincipalName(), clientId, ip, path,
                    "AUTHORIZE", true, null, 0L, null, ua);
        } catch (Exception e) {
            // best-effort — an audit hiccup must never break the authorize flow
        }
    }

    private HttpServletRequest currentRequest() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes sra) {
            return sra.getRequest();
        }
        return null;
    }

    private String extractIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        tracked.remove(authorization.getId());
        authorizationSessions.remove(authorization.getId());
    }

    /** Revokes active in-memory OAuth authorizations tied to a Passport device session. */
    public int revokeBySession(String sessionId) {
        int count = 0;
        for (var entry : authorizationSessions.entrySet()) {
            if (sessionId.equals(entry.getValue())) {
                OAuth2Authorization authorization = tracked.get(entry.getKey());
                if (authorization != null) { remove(authorization); count++; }
            }
        }
        return count;
    }

    /** Revokes all tracked OAuth authorizations except the current Passport session. */
    public int revokeAllExceptSession(String currentSessionId) {
        int count = 0;
        for (var authorization : tracked.values()) {
            if (currentSessionId == null || !currentSessionId.equals(authorizationSessions.get(authorization.getId()))) {
                remove(authorization); count++;
            }
        }
        return count;
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return current(delegate.findById(id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return current(delegate.findByToken(token, tokenType));
    }

    private OAuth2Authorization current(OAuth2Authorization authorization) {
        if (authorization == null) return null;
        org.springframework.security.core.Authentication original = authorization.getAttribute(java.security.Principal.class.getName());
        if (original != null && original.getPrincipal() instanceof io.aegis.passport.security.PassportUserPrincipal principal) {
            // A username can change or be reused. Bind tokens to the original ID,
            // and recheck lifecycle/ACL before codes, tokens or refresh grants are used.
            var user = users.findByUsername(authorization.getPrincipalName()).orElse(null);
            var client = clientRepo.findById(Long.parseLong(authorization.getRegisteredClientId())).orElse(null);
            if (user == null || !principal.getId().equals(user.getId()) || user.isNeedsSetup()
                    || !java.util.Objects.equals(user.getPassword(), principal.getPassword())
                    || !io.aegis.passport.client.ClientAccessPolicy.allowed(client, user)) {
                remove(authorization);
                return null;
            }
        }
        return authorization;
    }

    public int revokeByPrincipal(String username, String clientId) {
        String registeredId = clientId == null ? null : clientRepo.findByClientId(clientId).map(c -> c.getId().toString()).orElse("");
        int count = 0;
        for (var authorization : tracked.values()) {
            if (username.equals(authorization.getPrincipalName()) && (registeredId == null || registeredId.equals(authorization.getRegisteredClientId()))) {
                remove(authorization); count++;
            }
        }
        return count;
    }

    @org.springframework.transaction.event.TransactionalEventListener
    public void revokeDeviceGrants(io.aegis.passport.session.SessionService.RevokedSessions event) {
        for (String id : event.sessionIds()) revokeBySession(id);
    }
}
