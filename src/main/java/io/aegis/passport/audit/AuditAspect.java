package io.aegis.passport.audit;

import io.aegis.passport.security.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Records an {@link AuditEvent} for every method annotated with {@link Audit}.
 * Persistence is async so it never adds latency to the API response.
 */
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuditAspect {

    private final AuditLogService auditLogService;
    private final ExpressionParser spel = new SpelExpressionParser();

    @Around("@annotation(auditAnnotation)")
    public Object audit(ProceedingJoinPoint jp, Audit auditAnnotation) throws Throwable {
        long start = System.currentTimeMillis();
        String username = SecurityUtils.currentUsername();
        HttpServletRequest req = currentRequest();
        String ip = req != null ? extractIp(req) : null;
        String path = req != null ? req.getRequestURI() : null;
        String method = req != null ? req.getMethod() : null;
        String targetId = resolveTarget(jp, auditAnnotation.targetExpression());
        String params = req != null ? sanitizeParams(req) : null;
        String userAgent = req != null ? truncate(req.getHeader("User-Agent"), 500) : null;

        boolean success = true;
        String errorMsg = null;
        try {
            return jp.proceed();
        } catch (Throwable t) {
            success = false;
            errorMsg = t.getMessage();
            throw t;
        } finally {
            long elapsed = System.currentTimeMillis() - start;
            auditLogService.recordAsync(
                    auditAnnotation.module(), auditAnnotation.action(),
                    auditAnnotation.description(), username, targetId,
                    ip, path, method, success, errorMsg, elapsed, params, userAgent);
        }
    }

    /** Query + form parameters as a compact JSON-ish string with secrets redacted. */
    private String sanitizeParams(HttpServletRequest req) {
        try {
            Map<String, String[]> map = req.getParameterMap();
            if (map == null || map.isEmpty()) return null;
            return map.entrySet().stream()
                    .map(e -> e.getKey() + "=" + joinValues(e.getKey(), e.getValue()))
                    .collect(Collectors.joining("&"));
        } catch (Exception e) {
            return null;
        }
    }

    private String joinValues(String key, String[] values) {
        String value = values == null || values.length == 0 ? "" : values[values.length - 1];
        if (SENSITIVE_KEYS.stream().anyMatch(key::equalsIgnoreCase)) {
            return "***";
        }
        return truncate(value, 120);
    }

    private String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static final List<String> SENSITIVE_KEYS = List.of(
            "password", "oldPassword", "newPassword", "passwordEncrypted", "confirmPassword",
            "token", "access_token", "refresh_token", "code_verifier", "client_secret",
            "secret", "appKey", "clientSecret", "authorization", "envelope", "internalKey");

    private String resolveTarget(ProceedingJoinPoint jp, String expr) {
        if (expr == null || expr.isBlank()) return null;
        try {
            var sig = (org.aspectj.lang.reflect.MethodSignature) jp.getSignature();
            var ctx = new StandardEvaluationContext();
            String[] names = sig.getParameterNames();
            Object[] args = jp.getArgs();
            for (int i = 0; i < names.length; i++) ctx.setVariable(names[i], args[i]);
            Object val = spel.parseExpression(expr).getValue(ctx);
            return val != null ? val.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpServletRequest currentRequest() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes sra) return sra.getRequest();
        return null;
    }

    private String extractIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return req.getRemoteAddr();
    }
}
