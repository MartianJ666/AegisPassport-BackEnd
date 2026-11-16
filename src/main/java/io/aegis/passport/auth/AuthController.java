package io.aegis.passport.auth;

import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.auth.dto.AuthDtos.*;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.email.EmailService;
import io.aegis.passport.security.JwtTokenProvider;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.session.SessionService;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.UserService;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RsaTransportService rsa;
    private final LoginAttemptService loginAttemptService;
    private final VerificationCodeService verificationCodeService;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final UserRepository userRepository;
    private final SessionService sessionService;

    /** Self-service sign-up switch. Admin-initiated creation is never gated. */
    @Value("${passport.registration.self-service-enabled:true}")
    private boolean selfServiceRegistrationEnabled;

    @Value("${server.servlet.session.cookie.domain:}")
    private String cookieDomain;

    @PostMapping("/register")
    public ResponseEntity<ApiResult<Void>> register(
            @Valid @RequestBody RegisterRequest req,
            Authentication auth) {
        boolean isAdmin = auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin && !selfServiceRegistrationEnabled) {
            throw BusinessException.of(ErrorCode.REGISTRATION_DISABLED);
        }
        if (!isAdmin) {
            if (!emailService.isEnabled()) {
                throw BusinessException.of(ErrorCode.EMAIL_NOT_CONFIGURED);
            }
            if (req.getEmail() == null || !verificationCodeService.verify(req.getEmail(), req.getVerificationCode())) {
                throw BusinessException.of(ErrorCode.VERIFICATION_CODE_INVALID);
            }
        }
        req.setPassword(rsa.decrypt(req.getPassword()));
        userService.registerUser(req, isAdmin);
        auditLogService.recordAsync("auth", "REGISTER", "注册新账户", req.getUsername(), null,
                null, "/api/auth/register", "POST", true, null, 0L,
                "username=" + req.getUsername() + (isAdmin ? (req.getGroups() != null
                        ? ",groups=" + req.getGroups() : ",role=" + req.getRole()) : ""), null);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResult<LoginResponse>> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest httpReq,
            HttpServletResponse httpRes) {
        String username = req.getUsername();
        String clientIp = clientIp(httpReq);
        String userAgent = httpReq.getHeader("User-Agent");
        long startedAt = System.currentTimeMillis();
        if (loginAttemptService.isLocked(username)) {
            auditLogin(username, clientIp, userAgent, false, "账户已锁定", startedAt);
            long remaining = loginAttemptService.remainingLockSeconds(username);
            throw BusinessException.of(ErrorCode.ACCOUNT_LOCKED,
                    "账户已锁定，请 " + remaining + " 秒后重试");
        }
        String password = rsa.decrypt(req.getPassword());
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            auditLogin(username, clientIp, userAgent, false, "账户已禁用", startedAt);
            throw BusinessException.of(ErrorCode.ACCOUNT_DISABLED);
        } catch (LockedException e) {
            auditLogin(username, clientIp, userAgent, false, "账户已锁定", startedAt);
            throw BusinessException.of(ErrorCode.ACCOUNT_LOCKED);
        } catch (BadCredentialsException e) {
            loginAttemptService.loginFailed(username);
            int remaining = loginAttemptService.remainingAttempts(username);
            auditLogin(username, clientIp, userAgent, false,
                    "用户名或密码错误，剩余尝试次数：" + remaining, startedAt);
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS,
                    "用户名或密码错误，剩余尝试次数：" + remaining);
        } catch (InternalAuthenticationServiceException e) {
            auditLogin(username, clientIp, userAgent, false, "认证服务内部异常", startedAt);
            log.error("[登录] 认证服务异常 username={}", username, e);
            throw BusinessException.of(ErrorCode.LOGIN_SERVICE_UNAVAILABLE);
        } catch (AuthenticationException e) {
            // Covers UsernameNotFoundException (unknown account) and any other
            // provider failure. Keep the public response indistinguishable from
            // a bad password to avoid account enumeration.
            loginAttemptService.loginFailed(username);
            auditLogin(username, clientIp, userAgent, false, "用户名或密码错误", startedAt);
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "用户名或密码错误");
        }
        loginAttemptService.loginSucceeded(username);
        var principal = (io.aegis.passport.security.PassportUserPrincipal) authentication.getPrincipal();
        User loginUser = userRepository.findById(principal.getId()).orElseThrow(() ->
                new IllegalStateException("认证成功后找不到对应账号"));
        io.aegis.passport.session.AuthSession deviceSession;
        try {
            deviceSession = sessionService.create(loginUser, httpReq, "PASSWORD");
        } catch (RuntimeException e) {
            log.error("[登录] 无法创建设备会话 uid={}", principal.getId(), e);
            auditLogin(principal.getUsername(), clientIp, userAgent, false, "登录会话创建失败", startedAt);
            throw BusinessException.of(ErrorCode.LOGIN_SESSION_UNAVAILABLE);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        HttpSession session = httpReq.getSession(true);
        httpReq.changeSessionId();
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        String token = jwtTokenProvider.generate(principal.getId(), principal.getUsername(), deviceSession.getId());
        userService.recordLogin(principal.getUsername());
        auditLogin(principal.getUsername(), clientIp, userAgent, true, null, startedAt);

        Cookie tokenCookie = new Cookie("__Host-passport-token", token);
        tokenCookie.setPath("/");
        if (cookieDomain != null && !cookieDomain.isBlank() && !"localhost".equalsIgnoreCase(cookieDomain)) {
            // Authentication cookies are host-only.
        }
        tokenCookie.setHttpOnly(true);
        tokenCookie.setMaxAge(7 * 24 * 3600);
        tokenCookie.setSecure(true);
        // The consent page lives on sso.* and submits back to this origin
        // cross-site. Without SameSite=None the browser strips the JWT cookie on
        // that POST (Lax default), making the consent flow work only sometimes.
        tokenCookie.setAttribute("SameSite", "Lax");
        httpRes.addCookie(tokenCookie);

        LoginResponse body = new LoginResponse();
        body.setToken(token);
        body.setUserId(principal.getId());
        body.setUsername(principal.getUsername());
        return ResponseEntity.ok(ApiResult.ok(body));
    }

    private void auditLogin(String username, String ip, String userAgent,
                            boolean success, String errorMsg, long startedAt) {
        auditLogService.recordAsync("auth", success ? "LOGIN" : "LOGIN_FAILED",
                success ? "用户登录成功" : "用户登录失败",
                username, null, ip, "/api/auth/login", "POST",
                success, errorMsg, System.currentTimeMillis() - startedAt,
                "username=" + username, userAgent);
    }

    private String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResult<Void>> logout(HttpServletRequest req, HttpServletResponse res) {
        String operator = SecurityUtils.currentUsername();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String sid = SessionService.sessionId(req);
        if (sid != null && authentication != null && authentication.getPrincipal() instanceof io.aegis.passport.security.PassportUserPrincipal principal)
            sessionService.revokeOwned(principal.getId(), java.util.List.of(sid), operator, "LOGOUT");
        SecurityContextHolder.clearContext();
        HttpSession session = req.getSession(false);
        if (session != null) session.invalidate();
        Cookie c = new Cookie("__Host-passport-token", null);
        c.setPath("/");
        if (cookieDomain != null && !cookieDomain.isBlank() && !"localhost".equalsIgnoreCase(cookieDomain)) {
            // Authentication cookies are host-only.
        }
        c.setMaxAge(0);
        c.setSecure(true);
        c.setAttribute("SameSite", "Lax");
        res.addCookie(c);
        auditLogService.recordAsync("auth", "LOGOUT", "用户退出登录", operator, null,
                clientIp(req), "/api/auth/logout", "POST", true, null, 0L,
                null, req.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/send-verification-code")
    public ResponseEntity<ApiResult<Void>> sendCode(@Valid @RequestBody SendCodeRequest req) {
        if (!emailService.isEnabled()) {
            throw BusinessException.of(ErrorCode.EMAIL_NOT_CONFIGURED);
        }
        String code = verificationCodeService.generate(req.getEmail());
        emailService.sendVerificationCode(req.getEmail(), code);
        return ResponseEntity.ok(ApiResult.ok());
    }

    // NOTE: /api/auth/check-username was removed — it let unauthenticated callers
    // enumerate which usernames exist. Registration still reports USER_ALREADY_EXISTS
    // at submit time, so the live availability check is not needed.
}
