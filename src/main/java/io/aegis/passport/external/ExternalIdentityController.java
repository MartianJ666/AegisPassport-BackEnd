package io.aegis.passport.external;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.external.entity.ExternalIdentity;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/external-identities")
@RequiredArgsConstructor
public class ExternalIdentityController {
    private static final String BROWSER_COOKIE = "external_auth";
    private final ExternalProviderAuthService providerAuth;
    private final ExternalAccountService accountService;
    private final ThirdPartyLoginConfigService configService;
    private final PassportProperties props;
    private final AuditLogService auditLogService;
    private final UserRepository users;
    private final RsaTransportService rsa;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/providers")
    public ResponseEntity<ApiResult<List<ProviderView>>> providers() {
        return noStore(ApiResult.ok(List.of(
                view("oidc", "OpenID Connect")
        )));
    }

    @GetMapping
    public ResponseEntity<ApiResult<List<IdentityView>>> list() {
        Long userId = SecurityUtils.currentUserId();
        return noStore(ApiResult.ok(accountService.listForUser(userId).stream().map(IdentityView::from).toList()));
    }

    @GetMapping("/{provider}/start")
    public void start(@PathVariable String provider, HttpServletResponse response) throws IOException {
        ExternalProviderAuthService.StartResult result = providerAuth.start(provider);
        setBrowserCookie(provider, result.browserCookie(), result.transactionId(), response);
        noStoreHeaders(response);
        response.sendRedirect(result.url());
    }

    @PostMapping("/{provider}/bind")
    public ResponseEntity<ApiResult<Map<String, String>>> bind(@PathVariable String provider,
            @RequestBody BindRequest req, HttpServletResponse response) {
        Long userId = SecurityUtils.currentUserId();
        User user = users.findById(userId).orElseThrow(() -> BusinessException.of(ErrorCode.UNAUTHORIZED));
        String plain = rsa.decrypt(req.getPasswordEncrypted());
        if (!passwordEncoder.matches(plain, user.getPassword())) {
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "密码错误");
        }
        ExternalProviderAuthService.StartResult result = providerAuth.startLink(provider, user);
        setBrowserCookie(provider, result.browserCookie(), result.transactionId(), response);
        return ResponseEntity.ok(ApiResult.ok(Map.of("url", result.url())));
    }

    @GetMapping("/{provider}/callback")
    public void callback(@PathVariable String provider,
                         HttpServletRequest request, HttpServletResponse response) throws IOException {
        noStoreHeaders(response);
        String browser = null;
        try {
            // array string, so parse the first non-blank value ourselves.
            String tx = firstParam(request, "tx");
            String state = firstParam(request, "state");
            String code = firstParam(request, "code");
            String type = firstParam(request, "type");
            String error = firstParam(request, "error");
            if ("oidc".equals(provider) && state != null && tx == null) {
                ExternalProviderAuthService.ParsedState parsed = providerAuth.parseOidcState(state);
                tx = parsed.txId();
                state = parsed.state();
            }
            browser = cookie(request, browserCookieName(tx));
            if (browser == null) browser = cookie(request, BROWSER_COOKIE); // in-flight pre-upgrade requests
            clearCookie(provider, tx, response);
            clearCookie(provider, null, response);
            if (error != null) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录已取消或失败");
            ExternalProviderAuthService.CompleteResult result =
                    providerAuth.complete(provider, tx, state, code, type, browser, request, response);
            auditLogService.recordAsync("external-auth", result.linked() ? "LINK" : "LOGIN",
                    result.linked() ? "第三方账号绑定成功" : "第三方登录成功", null, provider,
                    clientIp(request), request.getRequestURI(), "GET", true, null, 0L, null, request.getHeader("User-Agent"));
            String target;
            if (result.linked()) {
                target = props.getFrontendUrl() + "/home?external=linked";
            } else {
                target = props.getFrontendUrl() + (result.needsSetup() ? "/auth/complete-external?external=complete" : "/auth/login?external=complete");
            }
            response.sendRedirect(target);
        } catch (Exception e) {
            log.warn("[外部登录] {} 回调失败: browserCookie={} err={}", provider, browser != null, e.toString());
            auditLogService.recordAsync("external-auth", "LOGIN_FAILED", "第三方登录失败", null, provider,
                    clientIp(request), request.getRequestURI(), "GET", false, "provider callback failed", 0L, null, request.getHeader("User-Agent"));
            response.sendRedirect(ExternalLoginFailure.target(props.getFrontendUrl(), provider, e,
                    "access_denied".equals(firstParam(request, "error"))));
        }
    }

    @PostMapping("/{id}/disconnect")
    @Audit(module = "external-auth", action = "DISCONNECT", description = "解绑第三方登录账号")
    public ResponseEntity<ApiResult<Void>> disconnect(@PathVariable Long id) {
        accountService.unbind(SecurityUtils.currentUserId(), id);
        return ResponseEntity.ok(ApiResult.ok());
    }

    private ProviderView view(String id, String name) {
        boolean enabled = providerAuth.isPubliclyAvailable(id);
        return new ProviderView(id, name, enabled);
    }

    private static String browserCookieName(String tx) {
        return tx != null && tx.matches("[A-Za-z0-9_-]{20,100}") ? BROWSER_COOKIE + "_" + tx : BROWSER_COOKIE;
    }

    private static void setBrowserCookie(String provider, String browserSecret, String tx, HttpServletResponse response) {
        Cookie cookie = new Cookie(browserCookieName(tx), browserSecret);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/external-identities/" + provider + "/callback");
        cookie.setMaxAge(300);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }

    private static <T> ResponseEntity<ApiResult<T>> noStore(ApiResult<T> body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Pragma", "no-cache").body(body);
    }

    private static void noStoreHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
    }

    private static String firstParam(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values == null) return null;
        for (String value : values) if (value != null && !value.isBlank()) return value;
        return null;
    }

    private static String cookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) if (name.equals(cookie.getName())) return cookie.getValue();
        return null;
    }

    private static void clearCookie(String provider, String tx, HttpServletResponse response) {
        Cookie cookie = new Cookie(browserCookieName(tx), "");
        cookie.setHttpOnly(true); cookie.setSecure(true);
        cookie.setPath("/api/external-identities/" + provider + "/callback");
        cookie.setMaxAge(0); cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        return xff != null && !xff.isBlank() ? xff.split(",")[0].trim() : request.getRemoteAddr();
    }

    public record ProviderView(String key, String name, boolean enabled) {}

    public record IdentityView(Long id, String provider, String displayName, String avatar,
                               Instant linkedAt, Instant lastAuthenticatedAt) {
        static IdentityView from(ExternalIdentity identity) {
            return new IdentityView(identity.getId(), identity.getProvider(), identity.getDisplayName(),
                    identity.getAvatar(), identity.getCreatedAt(), identity.getLastAuthenticatedAt());
        }
    }

    @Data
    public static class BindRequest {
        private String passwordEncrypted;
    }
}
