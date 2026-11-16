package io.aegis.passport.external;

import io.aegis.passport.security.PassportUserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Forces third-party-created accounts to finish email + password setup before
 * using the rest of the API. Only the setup flow, logout, profile read, the RSA
 * public key, provider start/callback, and audit beacon remain reachable.
 */
@Component
public class NeedsSetupFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof PassportUserPrincipal principal
                && principal.isNeedsSetup() && !isAllowed(request.getRequestURI())) {
            response.setStatus(403);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":403,\"errorCode\":\"EXTERNAL_SETUP_REQUIRED\",\"message\":\"请先完成账号设置\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isAllowed(String path) {
        if (path.startsWith("/api/external/setup")) return true;
        if (path.startsWith("/api/auth/logout")) return true;
        if (path.equals("/api/user/profile")) return true;
        if (path.equals("/api/rsa/public-key")) return true;
        if (path.startsWith("/api/audit/")) return true;
        if (path.startsWith("/api/external-identities/providers")) return true;
        if (path.startsWith("/api/external-identities/")
                && (path.endsWith("/start") || path.endsWith("/callback"))) return true;
        return false;
    }
}
