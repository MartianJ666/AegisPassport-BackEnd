package io.aegis.passport.oauth;

import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.auth.LoginAttemptService;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.consent.OAuthConsentRepository;
import io.aegis.passport.oauth.entity.OAuthClientAccount;
import io.aegis.passport.security.PassportUserPrincipal;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Temporary account switching for OAuth consent.
 *
 * <p>Endpoint used by the sso consent page when the user chooses "switch
 * account". It verifies the target account's credentials WITHOUT changing the
 * main login session, and returns a one-time {@code tempToken} that a later
 * {@code /oauth2/authorize} submission may carry so that SAS evaluates the
 * authorization with the target account's identity. The choice is also persisted
 * as a per-client preferred account for the current owner.
 */
@RestController
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
public class TempAuthController {

    private final AuthenticationManager authenticationManager;
    private final RsaTransportService rsa;
    private final TempAuthTokenService tempAuthTokenService;
    private final OAuthClientAccountRepository clientAccountRepository;
    private final OAuthConsentRepository consentRepository;
    private final AuditLogService auditLogService;
    private final LoginAttemptService loginAttemptService;
    private final io.aegis.passport.client.OAuthClientRepository clients;
    private final io.aegis.passport.user.UserRepository users;

    @PostMapping("/temp-login")
    public ResponseEntity<ApiResult<TempLoginResponse>> tempLogin(@RequestBody TempLoginRequest req) {
        String clientId = req.getClientId();
        String username = req.getUsername();
        if (clientId == null || clientId.isBlank() || username == null || username.isBlank()) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "clientId 和用户名不能为空");
        }
        // Same brute-force lockout as the public login endpoint — this endpoint
        // is public (permitAll) and previously had no attempt limiting at all.
        if (loginAttemptService.isLocked(username)) {
            throw BusinessException.of(ErrorCode.ACCOUNT_LOCKED, "账户已锁定，请稍后重试");
        }
        String password = rsa.decrypt(req.getPasswordEncrypted());
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException e) {
            loginAttemptService.loginFailed(username);
            auditLogService.recordAsync("oauth", "TEMP_LOGIN_FAILED", "应用账号切换登录失败",
                    username, null, null, "/api/oauth/temp-login", "POST",
                    false, "应用账号或密码错误", 0L, "clientId=" + clientId, null);
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "应用账号或密码错误");
        }
        loginAttemptService.loginSucceeded(username);
        var principal = (PassportUserPrincipal) authentication.getPrincipal();
        var client = clients.findByClientId(clientId).orElse(null);
        var targetUser = users.findByUsername(principal.getUsername()).orElse(null);
        if (targetUser == null || targetUser.isNeedsSetup() || !io.aegis.passport.client.ClientAccessPolicy.allowed(client, targetUser)) {
            throw BusinessException.of(ErrorCode.FORBIDDEN, "此账号无法访问该应用，请选择有权限的团队账号");
        }

        // Persist the preferred app account for this owner+client pair.
        String owner = SecurityUtils.currentUsername();
        if (owner != null && !owner.equals(principal.getUsername())) {
            OAuthClientAccount existing = clientAccountRepository
                    .findByClientIdAndOwnerUsername(clientId, owner).orElse(null);
            if (existing == null) {
                existing = OAuthClientAccount.builder()
                        .clientId(clientId).ownerUsername(owner)
                        .appUsername(principal.getUsername()).build();
            } else {
                existing.setAppUsername(principal.getUsername());
            }
            clientAccountRepository.save(existing);
        }

        String tempToken = tempAuthTokenService.create(clientId, principal.getUsername());
        boolean hasConsent = consentRepository
                .findByClientIdAndPrincipalName(clientId, principal.getUsername())
                .map(c -> !c.isExpired())
                .orElse(false);
        auditLogService.recordAsync("oauth", "TEMP_LOGIN", "应用账号切换",
                principal.getUsername(), owner, null, "/api/oauth/temp-login", "POST",
                true, null, 0L, "clientId=" + clientId + ",owner=" + owner, null);

        TempLoginResponse body = new TempLoginResponse();
        body.setTempToken(tempToken);
        body.setUsername(principal.getUsername());
        body.setHasConsent(hasConsent);
        return ResponseEntity.ok(ApiResult.ok(body));
    }

    @Data
    public static class TempLoginRequest {
        private String clientId;
        private String username;
        private String passwordEncrypted;
    }

    @Data
    public static class TempLoginResponse {
        private String tempToken;
        private String username;
        private boolean hasConsent;
    }
}
