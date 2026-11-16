package io.aegis.passport.security;

import io.aegis.passport.config.PassportProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CSRF protection for the OAuth consent approval.
 *
 * <p>Global CSRF is disabled because the consent SPA lives on another origin
 * (sso.*) and submits the approval as a cross-site POST back to the
 * authorization server — a CSRF token cookie can't be read cross-origin.
 * Spring's OAuth2 authorization server therefore has no CSRF check on the
 * {@code /oauth2/authorize} POST, which would let a malicious site auto-submit
 * an approval form on behalf of a logged-in user (silent consent CSRF).
 *
 * <p>This filter closes that gap with an Origin check: a browser always sends
 * {@code Origin} on cross-site POSTs, and a scripted form on an attacker's page
 * carries the attacker's own origin. We only accept {@code Origin} values that
 * are our own origins (issuer / frontend / consent base / configured CORS
 * origins). Requests with no Origin (native clients, which cannot use the
 * HttpOnly session cookie anyway) are allowed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ConsentCsrfOriginFilter extends OncePerRequestFilter {

    private final PassportProperties props;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only the consent-approval POST is the state-changing, cookie-authenticated
        // surface. The authorize GET (flow initiation) is not CSRF-sensitive.
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        return !request.getRequestURI().startsWith("/oauth2/authorize");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        if (origin != null && !origin.isBlank() && !isAllowedOrigin(origin)) {
            log.warn("[CSRF] 拒绝跨站授权提交 origin={}", origin);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":403,\"errorCode\":\"CSRF\",\"message\":\"跨站授权请求被拒绝\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isAllowedOrigin(String origin) {
        String normalized = origin.replaceAll("/+$", "");
        for (String candidate : allowedOrigins()) {
            if (normalized.equals(candidate.replaceAll("/+$", ""))) {
                return true;
            }
        }
        return false;
    }

    private List<String> allowedOrigins() {
        List<String> origins = new ArrayList<>();
        String corsOrigins = props.getCorsAllowedOrigins();
        if (corsOrigins != null) {
            for (String o : corsOrigins.split(",")) {
                if (!o.isBlank()) {
                    origins.add(o);
                }
            }
        }
        // The consent page may be served from any of these; all are trusted origins
        // of this deployment. Guard against null (unconfigured) values.
        for (String o : new String[]{props.getIssuer(), props.getFrontendUrl(),
                props.getConsent().getBaseUrl()}) {
            if (o != null && !o.isBlank()) {
                origins.add(o);
            }
        }
        return origins;
    }
}
