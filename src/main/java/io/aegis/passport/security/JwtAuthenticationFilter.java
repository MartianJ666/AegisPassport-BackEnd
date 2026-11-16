package io.aegis.passport.security;

import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reads the dashboard JWT from the {@code Authorization: Bearer …} header or
 * the {@code token} cookie, validates it, and places a
 * {@link PassportUserPrincipal} in the security context so every downstream
 * authority check has a populated principal to work with.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PermissionResolver permissionResolver;
    private final io.aegis.passport.session.SessionService sessions;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/.well-known/")
                || (path.startsWith("/api/auth/") && !path.equals("/api/auth/logout")
                    && !path.equals("/api/auth/register"))
                || path.startsWith("/api/public/") || path.equals("/api/config/login")
                || path.equals("/oauth-continue.js")
                || path.startsWith("/uploads/")
                || path.equals("/logout")
                || path.startsWith("/connect/")
                || path.startsWith("/oauth2/token")
                || path.startsWith("/oauth2/introspect")
                || path.startsWith("/oauth2/revoke")
                || path.startsWith("/oauth2/jwks")
                || path.startsWith("/h2-console");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            // AccountConfirmFilter may already have installed a request-scoped
            // temp identity. Never replace it with the dashboard JWT principal.
            if (Boolean.TRUE.equals(request.getAttribute(
                    AccountConfirmFilter.TEMP_IDENTITY_REQUEST_ATTR))) {
                chain.doFilter(request, response);
                return;
            }
            String token = extractToken(request);
            String uri = request.getRequestURI();
            boolean isAuthz = "/oauth2/authorize".equals(uri);
            log.info("[JWT] uri={} hasToken={} validated={}", uri,
                    StringUtils.hasText(token), token != null && tokenProvider.validate(token));
            if (StringUtils.hasText(token) && tokenProvider.validate(token)) {
                Long userId = tokenProvider.extractUserId(token);
                String username = tokenProvider.extractUsername(token);
                User user = userRepository.findById(userId).orElse(null);
                String sid = tokenProvider.extractSessionId(token);
                if (user != null && user.isEnabled() && !user.isLocked() && !user.isBanned() && sessions.active(sid, userId)) {
                    request.setAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE, sid);
                    sessions.touch(sid);
                    Set<String> permissions = permissionResolver.effectivePermissions(userId);
                    Set<String> roles = permissionResolver.roleCodes(userId);
                    PassportUserPrincipal principal = new PassportUserPrincipal(user, roles, permissions);
                    var auth = new UsernamePasswordAuthenticationToken(
                            principal, null, principal.getAuthorities());
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    log.info("[JWT] established principal {} for uri={}", username, uri);
                    // Do not write the JWT principal into the HTTP session here. The
                    // account-confirm filter may have deliberately replaced the
                    // request identity for an OAuth temp-account flow.
                } else {
                    clearAuthentication(request);
                    log.warn("[JWT] token valid but user missing/disabled/locked (uid={}) uri={}", userId, uri);
                }
            } else {
                if (StringUtils.hasText(token)) clearAuthentication(request);
                else {
                    var auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null && auth.getPrincipal() instanceof PassportUserPrincipal principal) {
                        var httpSession = request.getSession(false);
                        String sid = httpSession != null && httpSession.getAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE) instanceof String s ? s : null;
                        User currentUser = userRepository.findById(principal.getId()).orElse(null);
                        if (currentUser == null || !currentUser.isEnabled() || currentUser.isLocked()
                                || currentUser.isBanned() || !sessions.active(sid, principal.getId())) clearAuthentication(request);
                        else {
                            request.setAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE, sid);
                            sessions.touch(sid);
                            var freshPrincipal = new PassportUserPrincipal(currentUser,
                                    permissionResolver.roleCodes(currentUser.getId()),
                                    permissionResolver.effectivePermissions(currentUser.getId()));
                            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                                    freshPrincipal, null, freshPrincipal.getAuthorities()));
                        }
                    }
                }
            }
        } catch (Exception ex) {
            // Never let an auth-context build error masquerade as "not logged in":
            // surface it at warn so a broken principal is visible in logs.
            clearAuthentication(request);
            log.warn("[JWT] failed to establish security context: {}", ex.toString());
        }
        chain.doFilter(request, response);
    }

    private void clearAuthentication(HttpServletRequest request) {
        SecurityContextHolder.clearContext();
        var session = request.getSession(false);
        if (session != null) session.removeAttribute("SPRING_SECURITY_CONTEXT");
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("__Host-passport-token".equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }
}
