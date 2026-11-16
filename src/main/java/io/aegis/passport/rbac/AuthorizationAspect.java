package io.aegis.passport.rbac;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.rbac.annotation.RequireRole;
import io.aegis.passport.security.PassportUserPrincipal;
import io.aegis.passport.security.SecurityViolationService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * The one and only authorization enforcement point for annotated endpoints.
 * Reads the caller's authorities (role codes + effective permission codes, put
 * there at authentication time) and throws {@link BusinessException} with the
 * right {@link ErrorCode} — the global handler turns that into a clean 401/403
 * and records over-permission attempts as security violations.
 *
 * <p>Method-level annotations override class-level ones so a controller can
 * declare a default requirement and relax it per method.
 */
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuthorizationAspect {

    private final SecurityViolationService violationService;

    @Before("@within(io.aegis.passport.rbac.annotation.RequirePermission) "
            + "|| @annotation(io.aegis.passport.rbac.annotation.RequirePermission)")
    public void checkPermission(JoinPoint jp) {
        MethodSignature sig = (MethodSignature) jp.getSignature();
        RequirePermission ann = sig.getMethod().getAnnotation(RequirePermission.class);
        if (ann == null) {
            ann = jp.getTarget().getClass().getAnnotation(RequirePermission.class);
        }
        if (ann == null) {
            return;
        }
        Set<String> held = currentAuthorities();
        String[] required = ann.value();
        boolean ok = ann.requireAll()
                ? Arrays.stream(required).allMatch(held::contains)
                : Arrays.stream(required).anyMatch(held::contains);
        if (!ok) {
            recordViolation();
            throw BusinessException.of(ErrorCode.FORBIDDEN,
                    "缺少权限：" + String.join(ann.requireAll() ? " 且 " : " 或 ", required));
        }
    }

    @Before("@within(io.aegis.passport.rbac.annotation.RequireRole) "
            + "|| @annotation(io.aegis.passport.rbac.annotation.RequireRole)")
    public void checkRole(JoinPoint jp) {
        MethodSignature sig = (MethodSignature) jp.getSignature();
        RequireRole ann = sig.getMethod().getAnnotation(RequireRole.class);
        if (ann == null) {
            ann = jp.getTarget().getClass().getAnnotation(RequireRole.class);
        }
        if (ann == null) {
            return;
        }
        Set<String> held = currentAuthorities();
        boolean ok = Arrays.stream(ann.value())
                .map(r -> "ROLE_" + r.toUpperCase())
                .anyMatch(held::contains);
        if (!ok) {
            recordViolation();
            throw BusinessException.of(ErrorCode.FORBIDDEN,
                    "需要角色：" + String.join(" 或 ", ann.value()));
        }
    }

    private Set<String> currentAuthorities() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof PassportUserPrincipal)) {
            throw BusinessException.of(ErrorCode.UNAUTHORIZED);
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    /**
     * Fires when an authenticated user is denied an annotated endpoint. Pushes a
     * violation record (increments {@code violation_count}, writes a 越权访问
     * audit row) asynchronously via {@link SecurityViolationService}; the denial
     * response itself is unaffected. Best-effort: any failure is swallowed.
     */
    private void recordViolation() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !(auth.getPrincipal() instanceof PassportUserPrincipal pp)) {
                return;
            }
            if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes sra)) {
                return;
            }
            HttpServletRequest req = sra.getRequest();
            violationService.recordViolation(pp.getId(), pp.getUsername(),
                    req.getRequestURI(), req.getMethod(), extractIp(req));
        } catch (Exception e) {
            log.debug("记录越权访问失败: {}", e.getMessage());
        }
    }

    private String extractIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }
}
