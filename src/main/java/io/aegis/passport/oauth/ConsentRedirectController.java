package io.aegis.passport.oauth;

import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.oauth.entity.OAuthClientAccount;
import io.aegis.passport.security.PassportUserPrincipal;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Intercepts SAS's consent redirect and forwards the browser to the consent SPA
 * with an OPAQUE one-time token instead of the raw {@code client_id}/{@code scope}/
 * {@code state} query params. The consent page can live on a separate origin
 * ({@code sso.*}); only {@code ?token=…} shows in the address bar.
 *
 * <p>This controller runs on the authorization-server origin (where the user is
 * session-authenticated by SAS), so it can also enforce that the caller may
 * actually approve consents before letting them reach the consent page.
 */
@Controller
@RequiredArgsConstructor
public class ConsentRedirectController {

    private final ConsentTokenService tokenService;
    private final AccountConfirmTokenService accountConfirmTokenService;
    private final TempAuthTokenService tempAuthTokenService;
    private final PassportProperties props;
    private final OAuthClientAccountRepository clientAccountRepository;
    private final UserRepository userRepository;
    private final io.aegis.passport.security.PassportUserDetailsService userDetailsService;
    private final OAuthClientRepository clientRepository;
    private final org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizations;

    @GetMapping("/oauth2/consent-redirect")
    public void redirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String clientId = request.getParameter("client_id");
        String state = request.getParameter("state");
        String scope = request.getParameter("scope");

        String base = consentBaseUrl();

        // Any authenticated user may view and approve the consent form — this is
        // their own OAuth decision. (The separate consent-management page remains
        // gated on consent:read.)
        // The pending SAS request owns the identity, even after a temporary
        // switch or another tab changing the browser's main login cookie.
        var pending = state == null ? null : authorizations.findByToken(state, new org.springframework.security.oauth2.server.authorization.OAuth2TokenType("state"));
        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest original = pending == null ? null : pending.getAttribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());
        if (original == null || !java.util.Objects.equals(clientId, original.getClientId())) {
            response.sendRedirect(base + "/oauth2/consent?denied=1");
            return;
        }

        var policyClient=clientRepository.findByClientId(clientId==null?"":clientId).orElse(null);
        var policyUser=userRepository.findByUsername(pending.getPrincipalName()).orElse(null);
        if(!io.aegis.passport.client.ClientAccessPolicy.allowed(policyClient,policyUser)) {
            response.sendRedirect(base+"/oauth2/consent?denied=1");return;
        }

        String username = pending.getPrincipalName();
        if (username != null && !username.isBlank()) {
        }

        List<String> scopes = List.copyOf(original.getScopes());
        // Stash the current principal's username (which after an account-switch is the
        // switched account) in the consent token. The consent POST arrives on the sso
        // origin where the JSESSIONID is NOT shared with the pass origin, so the
        // session-held temp identity is unavailable there. Carrying the username in
        // the consent token lets the POST re-apply the correct principal for SAS.
        String currentUser = pending.getPrincipalName();
        String token = tokenService.create(clientId != null ? clientId : "",
                scopes, state, currentUser != null ? currentUser : "");
        response.sendRedirect(base + "/oauth2/consent?token=" + token);
    }

    /**
     * Public consent-info lookup. The opaque token is the credential — the SPA on
     * the consent origin fetches this to render scopes and learn where to submit.
     * Also returns the currently authenticated account ({@code currentUser}) so the
     * consent page can show "authorize as …", plus any preferred per-client account
     * previously chosen by that owner.
     */
    @GetMapping("/api/consent/info")
    @ResponseBody
    public ResponseEntity<ApiResult<Map<String, Object>>> info(@RequestParam String token) {
        ConsentTokenService.Entry entry = tokenService.get(token);
        if (entry == null) {
            throw BusinessException.of(ErrorCode.UNAUTHORIZED, "授权会话已失效，请重新发起授权");
        }
        String authorizeUrl = props.getIssuer().replaceAll("/+$", "") + "/oauth2/authorize";
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", entry.clientId() != null ? entry.clientId() : "");
        body.put("clientName", displayClientName(entry.clientId()));
        body.put("scope", entry.scopes());
        body.put("state", entry.state() != null ? entry.state() : "");
        body.put("authorizeUrl", authorizeUrl);
        var pending = entry.state() == null ? null : authorizations.findByToken(entry.state(), new org.springframework.security.oauth2.server.authorization.OAuth2TokenType("state"));
        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest original = pending == null ? null : pending.getAttribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());
        if (original != null && java.util.Objects.equals(original.getClientId(), entry.clientId())) {
            body.put("accountConfirmToken", accountConfirmTokenService.create(entry.clientId(), entry.username(), original.getAuthorizationRequestUri()));
        }

        // Prefer the account captured in the consent token (which works cross-origin on
        // sso.* even without a shared JWT cookie or after a temp-account switch),
        // falling back to the current security context if needed.
        if (entry.username() != null && !entry.username().isBlank()) {
            try {
                var details = userDetailsService.loadUserByUsername(entry.username());
                if (details instanceof io.aegis.passport.security.PassportUserPrincipal pp) {
                    body.put("currentUser", currentUserMap(pp));
                }
            } catch (Exception ignored) {
                SecurityUtils.currentPrincipal().ifPresent(p -> body.put("currentUser", currentUserMap(p)));
            }
        } else {
            SecurityUtils.currentPrincipal().ifPresent(p -> body.put("currentUser", currentUserMap(p)));
        }

        // Preferred app account previously chosen by this owner for this client.
        String owner = (entry.username() != null && !entry.username().isBlank())
                ? entry.username()
                : SecurityUtils.currentUsername();
        if (owner != null && entry.clientId() != null && !entry.clientId().isBlank()) {
            clientAccountRepository.findByClientIdAndOwnerUsername(entry.clientId(), owner)
                    .map(OAuthClientAccount::getAppUsername)
                    .filter(b -> !b.equals(owner))
                    .ifPresent(b -> body.put("preferredAccount", b));
        }
        return ResponseEntity.ok(ApiResult.ok(body));
    }

    /**
     * Account-confirmation lookup. The account-confirm gate redirects the browser
     * here (on sso.*) with the opaque {@code token} that backs the original
     * authorize URL. The SPA renders the current passport account and offers
     * "confirm" (back to authorize) or "switch account".
     */
    @GetMapping("/api/account-confirm/info")
    @ResponseBody
    public ResponseEntity<ApiResult<Map<String, Object>>> accountConfirmInfo(
            @RequestParam String token,
            @RequestParam(required = false) String tempToken) {
        AccountConfirmTokenService.Entry entry = accountConfirmTokenService.get(token);
        if (entry == null) {
            throw BusinessException.of(ErrorCode.UNAUTHORIZED, "确认会话已失效，请重新发起授权");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", entry.clientId() != null ? entry.clientId() : "");
        body.put("clientName", displayClientName(entry.clientId()));
        body.put("authorizeUrl", entry.authorizeUrl());
        boolean switched = false;
        // Optional temp token → the confirm page should show the SWITCHED account.
        if (tempToken != null && !tempToken.isBlank()) {
            TempAuthTokenService.Entry te = tempAuthTokenService.get(tempToken);
            if (te == null || !java.util.Objects.equals(te.clientId(), entry.clientId())) {
                throw BusinessException.of(ErrorCode.UNAUTHORIZED, "切换账号会话已失效，请重新发起授权");
            }
            var targetUser = userRepository.findByUsername(te.username()).orElse(null);
            if (targetUser == null || targetUser.isNeedsSetup() || !io.aegis.passport.client.ClientAccessPolicy.allowed(clientRepository.findByClientId(entry.clientId()).orElse(null), targetUser)) {
                throw BusinessException.of(ErrorCode.FORBIDDEN, "此账号无法访问该应用");
            }
            if (te != null) {
                try {
                    var details = userDetailsService.loadUserByUsername(te.username());
                    if (details instanceof io.aegis.passport.security.PassportUserPrincipal pp) {
                        body.put("currentUser", currentUserMap(pp));
                        body.put("tempToken", tempToken);
                        switched = true;
                    }
                } catch (Exception ignored) {
                    // fall through to the snapshot account below
                }
            }
        }
        if (!switched) {
            // Prefer the account captured in the confirm token (the JWT login at the
            // moment the authorize request was gated) over the servlet session, which
            // may hold a stale account from an earlier login.
            if (entry.username() != null && !entry.username().isBlank()) {
                try {
                    var details = userDetailsService.loadUserByUsername(entry.username());
                    if (details instanceof io.aegis.passport.security.PassportUserPrincipal pp) {
                        body.put("currentUser", currentUserMap(pp));
                    }
                } catch (Exception ignored) {
                    SecurityUtils.currentPrincipal().ifPresent(p -> body.put("currentUser", currentUserMap(p)));
                }
            } else {
                SecurityUtils.currentPrincipal().ifPresent(p -> body.put("currentUser", currentUserMap(p)));
            }
            // Preferred per-client account previously chosen by this owner.
            String owner = entry.username() != null ? entry.username() : SecurityUtils.currentUsername();
            if (owner != null && entry.clientId() != null && !entry.clientId().isBlank()) {
                clientAccountRepository.findByClientIdAndOwnerUsername(entry.clientId(), owner)
                        .map(OAuthClientAccount::getAppUsername)
                        .filter(b -> !b.equals(owner))
                        .ifPresent(b -> body.put("preferredAccount", b));
            }
        }
        return ResponseEntity.ok(ApiResult.ok(body));
    }

    private String displayClientName(String clientId) {
        if (clientId == null || clientId.isBlank()) return "此应用";
        return clientRepository.findByClientId(clientId)
                .map(c -> c.getClientName())
                .filter(name -> name != null && !name.isBlank())
                .orElse("此应用");
    }

    private Map<String, Object> currentUserMap(PassportUserPrincipal p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", p.getUsername());
        String nickname = p.getUsername();
        String avatar = null;
        User user = userRepository.findByUsername(p.getUsername()).orElse(null);
        if (user != null) {
            if (user.getNickname() != null && !user.getNickname().isBlank()) nickname = user.getNickname();
            avatar = user.getAvatar();
        }
        m.put("nickname", nickname);
        if (avatar != null) m.put("avatar", avatar);
        boolean admin = p.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        m.put("role", admin ? "admin" : "member");
        return m;
    }

    private String consentBaseUrl() {
        String base = props.getConsent().getBaseUrl();
        if (base == null || base.isBlank()) {
            base = props.getFrontendUrl();
        }
        return base.replaceAll("/+$", "");
    }
}
