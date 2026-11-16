package io.aegis.passport.security;

import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.oauth.AccountConfirmTokenService;
import io.aegis.passport.oauth.TempAuthTokenService;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Account-confirmation gate for every OAuth authorize request.
 *
 * <p>When a logged-in user starts {@code GET /oauth2/authorize}, this filter
 * forces them through an account-confirm page on the sso origin FIRST (showing
 * which account will be used, with an option to switch). Only after confirming
 * (the request carries {@code aegis_account_confirmed=1}) does the request pass
 * through to Spring Authorization Server, which then proceeds as normal: silent
 * code if consent already exists, otherwise the consent/authorization page.
 *
 * <p>When the user switched to a different account (the request carries a
 * one-time {@code aegis_temp_token}), this filter swaps the security context AND
 * the session to that account for the authorize request. SAS then issues the code
 * for the switched account; the main session's account is untouched.
 *
 * <p>Because an OAuth authorization spans two requests — the {@code GET
 * /oauth2/authorize} that decides consent and the {@code POST /oauth2/authorize}
 * consent submission — the switched identity must survive across both. SAS binds
 * the in-flight authorization to the principal seen on the GET and rejects the
 * consent POST with HTTP 400 when the POST's principal differs. So when the GET
 * applies a temp identity we also record it in the session, and re-apply it on
 * the consent POST so SAS evaluates the submission as the same switched account.
 *
 * <p>Authenticated detection is based on the {@code token} JWT cookie (the current
 * browser login), NOT the servlet session — this filter runs before the JWT filter
 * populates the security context, so relying on the session could show a stale
 * account from an earlier login.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AccountConfirmFilter extends OncePerRequestFilter {

    /** Session attribute carrying the switched account until the consent POST lands. */
    static final String TEMP_IDENTITY_ATTR = "aegis.temp.identity";
    static final String TEMP_IDENTITY_REQUEST_ATTR = "aegis.temp.identity.applied";

    /** Temp token TTL (see {@link TempAuthTokenService}) — bound switches expire with it. */
    private static final long TEMP_TTL_SECONDS = 300;

    private final AccountConfirmTokenService accountConfirmTokenService;
    private final TempAuthTokenService tempAuthTokenService;
    private final PassportUserDetailsService userDetailsService;
    private final JwtTokenProvider tokenProvider;
    private final PassportProperties props;
    private final UserRepository userRepository;
    private final OAuthClientRepository clientRepository;
    private final io.aegis.passport.oauth.ConsentTokenService consentTokenService;
    private final io.aegis.passport.session.SessionService sessions;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String method = request.getMethod();
        if (log.isDebugEnabled()) {
            log.debug("[ACF-SNF] uri={} method={} isAuthorize={} skip={}",
                    uri, method, "/oauth2/authorize".equals(uri),
                    (!"/oauth2/authorize".equals(uri)) || (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)));
        }
        // Gate browser-driven authorize GETs, and process the consent POST so the
        // switched account can be re-applied for the SAS consent submission.
        if (!"/oauth2/authorize".equals(uri)) {
            return true;
        }
        return !"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (log.isDebugEnabled() && "/oauth2/authorize".equals(request.getRequestURI())) {
            log.debug("[ACF-ENTER] method={} token={} client_id={}",
                    request.getMethod(), request.getParameter("token"), request.getParameter("client_id"));
        }
        // Determine the authenticated account from the JWT cookie (current login),
        // independent of the servlet session which may hold a stale account.
        String jwt = extractTokenCookie(request);
        String username = null;
        if (StringUtils.hasText(jwt)) {
            try {
                Long uid = tokenProvider.validate(jwt) ? tokenProvider.extractUserId(jwt) : null;
                String sid = uid == null ? null : tokenProvider.extractSessionId(jwt);
                User current = uid == null ? null : userRepository.findById(uid).orElse(null);
                if (current != null && current.isEnabled() && !current.isLocked() && !current.isBanned()
                        && sessions.active(sid, uid)) {
                    username = current.getUsername();
                    request.setAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE, sid);
                    sessions.touch(sid);
                } else {
                    clearAuthentication(request);
                }
            } catch (Exception ex) {
                clearAuthentication(request);
                log.warn("[AccountConfirm] device session validation failed");
            }
        } else {
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
            if (currentAuth != null && currentAuth.getPrincipal() instanceof PassportUserPrincipal principal) {
                HttpSession httpSession = request.getSession(false);
                String sid = httpSession != null && httpSession.getAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE) instanceof String s ? s : null;
                User current = userRepository.findById(principal.getId()).orElse(null);
                if (current == null || !current.isEnabled() || current.isLocked() || current.isBanned()
                        || !sessions.active(sid, principal.getId())) clearAuthentication(request);
                else {
                    username = current.getUsername();
                    request.setAttribute(io.aegis.passport.session.SessionService.SESSION_ATTRIBUTE, sid);
                    sessions.touch(sid);
                }
            }
        }
        // Consent POST (SAS consent-form submission): re-apply the switched
        // account recorded on the authorize GET, so the submission is evaluated for
        // the same principal the in-flight authorization was created for. Without
        // this SAS rejects the POST with HTTP 400 (principal mismatch).
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            if (log.isDebugEnabled()) {
                HttpSession dbgSess = request.getSession(false);
                log.debug("[DBG-POST] uri={} params(token={},client_id={},state={}) sess={}",
                        request.getRequestURI(),
                        request.getParameter("token"),
                        request.getParameter("client_id"),
                        request.getParameter("state") != null ? request.getParameter("state") : "null",
                        dbgSess != null ? dbgSess.getId() : "null");
            }
            if (!reapplyTempIdentity(request, response)) return;
            // Finish the form POST on Passport itself. A direct 302 to the client
            // is subject to the consent document's form-action CSP in Chromium,
            // even though SAS already validated the client's redirect URI.
            var navigation = new ConsentNavigationResponse(response);
            chain.doFilter(request, navigation);
            if (navigation.completed) consentTokenService.revoke(request.getParameter("token"));
            return;
        }

        String confirmation = request.getParameter("aegis_confirm_token");
        if (confirmation != null) {
            var confirmed = accountConfirmTokenService.get(confirmation);
            if (confirmed == null || !java.util.Objects.equals(confirmed.clientId(), request.getParameter("client_id"))
                    || (request.getParameter("aegis_temp_token") == null && !java.util.Objects.equals(confirmed.username(), username))) {
                invalidConfirmation(response);
                return;
            }
        }
        // Authenticate the explicitly selected account before ACL checks. Never
        // silently fall back to the main account if a switch expired or failed.
        if (request.getParameter("aegis_temp_token") != null) {
            username = applyTempIdentity(request);
            if (username == null) {
                clearAuthentication(request);
                invalidConfirmation(response);
                return;
            }
        }

        // Unauthenticated — let SAS send the browser to the login page.
        if (username == null) {
            log.info("[ACF] authorize without JWT-cookie identity; confirmed={} ctxAuth={}",
                    request.getParameter("aegis_account_confirmed"),
                    SecurityContextHolder.getContext() != null
                            ? SecurityContextHolder.getContext().getAuthentication() : null);
            chain.doFilter(request, response);
            return;
        }

        var setupUser = userRepository.findByUsername(username).orElse(null);
        if (setupUser != null && setupUser.isNeedsSetup()) {
            String original = request.getRequestURL() + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
            response.sendRedirect(props.getFrontendUrl() + "/auth/complete-external?redirect=" + URLEncoder.encode(original, StandardCharsets.UTF_8));
            return;
        }

        // Banned accounts must not be able to drive the OAuth flow. The violation
        // filter only guards /api/** on the API chain, so without this check a
        // banned user's still-valid JWT could complete /oauth2/authorize and the
        // consent submission and obtain authorization codes for every connected app.
        User bannedCheck = userRepository.findByUsername(username).orElse(null);
        if (bannedCheck != null && bannedCheck.isBanned()) {
            log.warn("[安全] 被封禁用户 {} 尝试发起 OAuth 授权", username);
            response.setStatus(403);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":403,\"errorCode\":\"ACCOUNT_BANNED\",\"message\":\"账户已被封禁\"}");
            return;
        }

        // Role-based access control: enforce the client's allowed_roles on every
        // authorize request (regardless of whether consent already exists). Users
        // without a permitted role are sent to the consent page's denied state.
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            var clientOpt = clientRepository.findByClientId(clientId);
            if (clientOpt.isPresent()) {
                var client = clientOpt.get();
                var policyUser=userRepository.findByUsername(username).orElse(null);
                if(!io.aegis.passport.client.ClientAccessPolicy.allowed(client,policyUser)) {
                    sendDenied(response);return;
                }
            }
        }

        // Runs on every authorized authorize request so the binding always exists

        // Post-confirmation re-entry: apply temp identity if present, then pass through.
        if ("1".equals(request.getParameter("aegis_account_confirmed"))) {
            // Confirmed as the main account (no switch) — drop any stale switch so a
            // later consent POST isn't evaluated as a previously-switched account.
            if (request.getParameter("aegis_temp_token") == null) {
                clearTempIdentity(request);
            }
            var ctx = SecurityContextHolder.getContext();
            var ctxAuth = ctx != null ? ctx.getAuthentication() : null;
            log.info("[ACF] confirmed authorize pass-through for client {}; ctxAuth={} authenticated={}",
                    clientId,
                    ctxAuth != null ? ctxAuth.getClass().getSimpleName() : "null",
                    ctxAuth != null ? ctxAuth.isAuthenticated() : false);
            // The Spring Authorization Server authorization endpoint resolves the
            // requesting principal from the SecurityContextHolder. On this pass the
            // JWT filter may not have populated it (it runs after the SAS endpoint
            // filter on the authorization-server chain), so re-establish the
            // confirmed account here to avoid SAS rejecting the request with
            // "OAuth 2.0 Parameter: principal".
            ensureAuthenticated(request, username);
            chain.doFilter(request, response);
            return;
        }

        // Authenticated and not yet confirmed — redirect to the sso account page,
        // binding the CURRENT JWT account into the token so the confirm page shows it.
        // A brand-new flow starts fresh: remove any leftover switch from a prior flow.
        clearTempIdentity(request);
        String fullUrl = request.getRequestURL().toString()
                + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
        String token = accountConfirmTokenService.create(
                clientId != null ? clientId : "", username, fullUrl);
        String base = props.getConsent().getBaseUrl();
        if (base == null || base.isBlank()) {
            base = props.getFrontendUrl();
        }
        base = base.replaceAll("/+$", "");
        String dest = base + "/oauth2/account-confirm?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
        log.debug("[AccountConfirm] gating authorize for client {} as {} → {}", clientId, username, dest);
        response.sendRedirect(dest);
    }

    private void sendDenied(HttpServletResponse response) throws IOException {
        String base = props.getConsent().getBaseUrl();
        if (base == null || base.isBlank()) {
            base = props.getFrontendUrl();
        }
        base = base.replaceAll("/+$", "");
        response.sendRedirect(base + "/oauth2/consent?denied=1");
    }

    private void invalidConfirmation(HttpServletResponse response) throws IOException {
        String base = props.getConsent().getBaseUrl();
        response.sendRedirect((base == null || base.isBlank() ? props.getFrontendUrl() : base).replaceAll("/+$", "") + "/oauth2/account-confirm?invalid=1");
    }

    private void clearAuthentication(HttpServletRequest request) {
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) session.removeAttribute("SPRING_SECURITY_CONTEXT");
    }

    private static Set<String> splitIds(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim).filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private String extractTokenCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("__Host-passport-token".equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    /**
     * Ensures the SecurityContextHolder carries an authenticated principal for
     * {@code username} (from the JWT cookie). The authorization-server filter
     * chain may not have populated it by the time SAS's authorize endpoint runs;
     * without it SAS rejects the confirmed request with
     * {@code OAuth 2.0 Parameter: principal}. Only fills when the context is
     * missing/anonymous — never replaces an existing temp/switch identity.
     */
    private void ensureAuthenticated(HttpServletRequest request, String username) {
        if (!StringUtils.hasText(username)) {
            return;
        }
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (Boolean.TRUE.equals(request.getAttribute(TEMP_IDENTITY_REQUEST_ATTR))) {
            return;
        }
        try {
            UserDetails details = userDetailsService.loadUserByUsername(username);
            var auth = new UsernamePasswordAuthenticationToken(
                    details, null, details.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.info("[ACF] re-established authenticated principal {} for confirmed authorize", username);
        } catch (Exception e) {
            log.warn("[ACF] failed to establish principal for {}: {}", username, e.toString());
        }
    }

    /**
     * If the confirmed authorize request carries a one-time temp token, swap the
     * security context (and the session) to the switched account so SAS issues the
     * code for that account. Consumes the token — single use.
     */
    private String applyTempIdentity(HttpServletRequest request) {
        String tempToken = request.getParameter("aegis_temp_token");
        if (tempToken == null || tempToken.isBlank()) {
            return null;
        }
        TempAuthTokenService.Entry entry = tempAuthTokenService.consume(tempToken);
        if (entry == null) {
            return null;
        }
        // A switch token is minted for one client — only honor it on an authorize
        // for that client, or a leaked token could authorize any app as the target.
        String clientId = request.getParameter("client_id");
        if (clientId == null || !clientId.equals(entry.clientId())) {
            log.warn("[AccountConfirm] 拒绝 temp token:为客户端 {} 签发,用于 {}", entry.clientId(), clientId);
            return null;
        }
        try {
            var user = userRepository.findByUsername(entry.username()).orElse(null);
            var client = clientRepository.findByClientId(clientId).orElse(null);
            if (user == null || user.isNeedsSetup() || !io.aegis.passport.client.ClientAccessPolicy.allowed(client, user)) return null;
            UserDetails details = userDetailsService.loadUserByUsername(entry.username());
            var auth = new UsernamePasswordAuthenticationToken(
                    details, null, details.getAuthorities());
            // Swap only the request-scoped security context (SAS reads it for this
            // authorize) plus a flow-scoped session binding. We deliberately do NOT
            // write SPRING_SECURITY_CONTEXT into the shared session: the switched
            // identity must not leak into other requests on the same session.
            SecurityContextHolder.getContext().setAuthentication(auth);
            request.setAttribute(TEMP_IDENTITY_REQUEST_ATTR, Boolean.TRUE);
            var sess = request.getSession(true);
            sess.setAttribute(TEMP_IDENTITY_ATTR,
                    new TempIdentity(entry.clientId(), entry.username(), Instant.now()));
            log.info("[AccountConfirm] authorize as {} for client {}", entry.username(), entry.clientId());
            return entry.username();
        } catch (Exception e) {
            log.warn("[AccountConfirm] failed to build principal for {}: {}", entry.username(), e.toString());
            return null;
        }
    }

    /**
     * Re-applies the switched account on the SAS consent POST, keyed to the client
     * the switch was made for. The temp token itself is already consumed (single
     * use) — the session holds the binding recorded by {@link #applyTempIdentity}.
     */
    private boolean reapplyTempIdentity(HttpServletRequest request, HttpServletResponse response) throws IOException {
        var entry = consentTokenService.get(request.getParameter("token"));
        if (entry == null || !java.util.Objects.equals(entry.clientId(), request.getParameter("client_id"))
                || !java.util.Objects.equals(entry.state(), request.getParameter("state"))) {
            clearAuthentication(request);
            response.setStatus(400);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":400,\"message\":\"授权会话无效或已过期，请从应用重新发起登录\"}");
            return false;
        }
        var user = userRepository.findByUsername(entry.username()).orElse(null);
        var client = clientRepository.findByClientId(entry.clientId()).orElse(null);
        if (user == null || user.isNeedsSetup() || !io.aegis.passport.client.ClientAccessPolicy.allowed(client, user)) {
            clearAuthentication(request);
            response.setStatus(403);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":403,\"message\":\"当前账号无法访问此应用\"}");
            return false;
        }
        UserDetails details = userDetailsService.loadUserByUsername(entry.username());
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities()));
        request.setAttribute(TEMP_IDENTITY_REQUEST_ATTR, Boolean.TRUE);
        return true;
    }

    private void clearTempIdentity(HttpServletRequest request) {
        HttpSession sess = request.getSession(false);
        if (sess != null) {
            sess.removeAttribute(TEMP_IDENTITY_ATTR);
        }
    }

    /** Binding of a switched account to a client, held in the session across the OAuth flow. */
    private record TempIdentity(String clientId, String username, Instant createdAt) {}

    static final class ConsentNavigationResponse extends HttpServletResponseWrapper {
        boolean completed;
        ConsentNavigationResponse(HttpServletResponse response) { super(response); }

        @Override
        public void sendRedirect(String location) throws IOException {
            completed = true;
            // Location comes exclusively from SAS's authorization result, never
            // from a browser-provided next/redirect parameter. Keep OAuth's URI,
            // state, PKCE and consent validation in SAS unchanged.
            String escaped = org.springframework.web.util.HtmlUtils.htmlEscape(location, "UTF-8");
            setStatus(HttpServletResponse.SC_OK);
            setHeader("Cache-Control", "no-store");
            setHeader("Referrer-Policy", "no-referrer");
            setContentType("text/html;charset=UTF-8");
            getWriter().write("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                    + "<meta name=\"referrer\" content=\"no-referrer\"><title>正在返回应用</title></head>"
                    + "<body><p>授权处理完成，正在返回应用…</p><a id=\"oauth-continue\" href=\""
                    + escaped + "\">继续返回应用</a><script src=\"/oauth-continue.js\"></script></body></html>");
        }
    }
}
