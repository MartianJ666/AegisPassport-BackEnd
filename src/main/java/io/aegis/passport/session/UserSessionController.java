package io.aegis.passport.session;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.systemconfig.SystemConfigService;
import io.aegis.passport.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.*;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import io.aegis.passport.oauth.AuditedOAuth2AuthorizationService;

@RestController
@RequestMapping("/api/user/sessions")
@RequiredArgsConstructor
public class UserSessionController {
    private final SessionService sessions;
    private final UserRepository users;
    private final RsaTransportService rsa;
    private final PasswordEncoder passwords;

    @GetMapping
    @Audit(module="auth", action="SESSION_LIST", description="查看登录设备")
    public ResponseEntity<ApiResult<List<SessionService.SessionView>>> list(HttpServletRequest request) {
        return ResponseEntity.ok(ApiResult.ok(sessions.list(SecurityUtils.currentUserId(), SessionService.sessionId(request))));
    }

    @PostMapping("/revoke")
    @Audit(module="auth", action="SESSION_REVOKE", description="注销登录设备")
    public ResponseEntity<ApiResult<Map<String,Object>>> revoke(@Valid @RequestBody RevokeRequest req, HttpServletRequest request) {
        var user=users.findById(SecurityUtils.currentUserId()).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        String password=rsa.decryptStrict(req.getPasswordEncrypted());
        if(!passwords.matches(password,user.getPassword())) throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS,"密码错误");
        String current = SessionService.sessionId(request);
        int count=sessions.revokeOwned(user.getId(), req.getSessionIds(), user.getUsername(), "USER_REVOKE");
        boolean currentRevoked=current!=null && req.getSessionIds().contains(current);
        if(currentRevoked){var session=request.getSession(false);if(session!=null)session.invalidate();}
        return ResponseEntity.ok(ApiResult.ok(Map.of("revokedCount",count,"currentRevoked",currentRevoked)));
    }

    @PostMapping("/delete-offline")
    @Audit(module="auth", action="SESSION_DELETE_OFFLINE", description="删除离线登录设备记录")
    public ResponseEntity<ApiResult<Integer>> deleteOffline(@Valid @RequestBody RevokeRequest req) {
        var user=users.findById(SecurityUtils.currentUserId()).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        if(!passwords.matches(rsa.decryptStrict(req.getPasswordEncrypted()),user.getPassword())) throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS,"密码错误");
        return ResponseEntity.ok(ApiResult.ok(sessions.deleteOwnedOffline(user.getId(),req.getSessionIds())));
    }

    @Data
    public static class RevokeRequest { @NotBlank private String passwordEncrypted; @jakarta.validation.constraints.NotEmpty @jakarta.validation.constraints.Size(max=100) private List<@NotBlank String> sessionIds=List.of(); }
}

@RestController
@RequestMapping("/api/config/admin/security")
@RequiredArgsConstructor
class SessionAdminController {
    private final SystemConfigService config;
    private final SessionService sessions;
    private final OAuth2AuthorizationService oauthAuthorizations;
    private final UserRepository users;
    private final RsaTransportService rsa;
    private final PasswordEncoder passwords;
    private final io.aegis.passport.auth.LoginAttemptService attempts;

    @GetMapping("/session-policy")
    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_VIEW)
    public ResponseEntity<ApiResult<Map<String,Boolean>>> policy(){return ResponseEntity.ok(ApiResult.ok(Map.of("allowMultipleDevices",config.allowMultipleDevices())));}

    @PutMapping("/session-policy")
    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
    @Audit(module="security", action="DEVICE_POLICY_CHANGED", description="修改多设备登录策略")
    public ResponseEntity<ApiResult<Void>> policy(@RequestBody Map<String,Object> body){Object value=body.get("allowMultipleDevices");if(!(value instanceof Boolean b))throw BusinessException.of(ErrorCode.BAD_REQUEST,"allowMultipleDevices 必须是布尔值");config.setAllowMultipleDevices(b);return ResponseEntity.ok(ApiResult.ok());}

    @PostMapping("/global-logout")
    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
    @Audit(module="security", action="ADMIN_GLOBAL_LOGOUT", description="管理员注销全平台登录状态")
    public ResponseEntity<ApiResult<Map<String,Integer>>> globalLogout(@Valid @RequestBody GlobalLogoutRequest body, HttpServletRequest request){
        var user = users.findById(SecurityUtils.currentUserId()).orElseThrow(() -> BusinessException.of(ErrorCode.UNAUTHORIZED));
        if (attempts.isLocked(user.getUsername())) throw BusinessException.of(ErrorCode.ACCOUNT_LOCKED);
        if (!passwords.matches(rsa.decryptStrict(body.passwordEncrypted()), user.getPassword())) {
            attempts.loginFailed(user.getUsername());
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "密码错误，未注销任何设备");
        }
        attempts.loginSucceeded(user.getUsername());
        String current = SessionService.sessionId(request);
        int count=sessions.globalLogout(current,SecurityUtils.currentUsername());
        int oauth = 0;
        boolean revokeOAuth = body.revokeOAuthSessions();
        if (revokeOAuth && oauthAuthorizations instanceof AuditedOAuth2AuthorizationService audited) oauth = audited.revokeAllExceptSession(current);
        return ResponseEntity.ok(ApiResult.ok(Map.of("revokedSessions",count,"revokedOAuthSessions",oauth)));
    }
    public record GlobalLogoutRequest(@NotBlank String passwordEncrypted, boolean revokeOAuthSessions) {}
}
