package io.aegis.passport.external;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.external.entity.ExternalIdentity;
import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.security.JwtTokenProvider;
import io.aegis.passport.security.PassportUserPrincipal;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.UserService;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class ExternalLoginService {
    private final ExternalIdentityRepository identities;
    private final UserRepository users;
    private final UserService userService;
    private final PermissionResolver permissionResolver;
    private final JwtTokenProvider jwtTokenProvider;
    private final io.aegis.passport.session.SessionService sessionService;

    /** Self-service sign-up switch: gates first-login auto-creation of accounts. */
    @Value("${passport.registration.self-service-enabled:true}")
    private boolean selfServiceRegistrationEnabled;

    /** Authenticates the resolved user and returns whether the account still needs setup. */
    @Transactional
    public boolean authenticate(ExternalProviderIdentity external, HttpServletRequest request, HttpServletResponse response) {
        User user = resolveUser(external);
        if (!user.isEnabled()) throw BusinessException.of(ErrorCode.ACCOUNT_DISABLED);
        if (user.isLocked() || user.isBanned()) throw BusinessException.of(ErrorCode.ACCOUNT_LOCKED);
        reissue(user, request, response);
        return user.isNeedsSetup();
    }

    /**
     * (Re)issues the dashboard session + JWT cookie for the given user. Used after
     * the external login callback and after onboarding changes the username.
     */
    @Transactional
    public String reissue(User user, HttpServletRequest request, HttpServletResponse response) {
        var deviceSession = sessionService.create(user, request, "EXTERNAL");
        var principal = new PassportUserPrincipal(user, permissionResolver.roleCodes(user.getId()),
                permissionResolver.effectivePermissions(user.getId()));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
        HttpSession session = request.getSession(true);
        request.changeSessionId();
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        String token = jwtTokenProvider.generate(user.getId(), user.getUsername(), deviceSession.getId());
        Cookie cookie = new Cookie("__Host-passport-token", token);
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(7 * 24 * 3600);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
        userService.recordLogin(user.getUsername());
        return token;
    }

    private User resolveUser(ExternalProviderIdentity external) {
        ExternalIdentity existing = identities.findByProviderAndIssuerAndProviderSubject(
                external.provider(), external.issuer(), external.subject()).orElse(null);
        if (existing != null) {
            existing.setLastAuthenticatedAt(Instant.now());
            identities.save(existing);
            User linked = existing.getUser();
            String verified = normalizeEmail(external.verifiedEmail());
            if (verified != null && verified.equalsIgnoreCase(linked.getEmail())) {
                linked.setEmailVerified(true); users.save(linked);
            }
            return linked;
        }
        if (!selfServiceRegistrationEnabled) {
            throw BusinessException.of(ErrorCode.REGISTRATION_DISABLED);
        }
        // Brand-new identity: create a temporary user (needsSetup=true) and link it.
        // A provider email that collides is left unset so onboarding can offer merge.
        String email = normalizeEmail(external.verifiedEmail());
        User user = userService.createExternalUser(email, external.displayName(), external.avatar());
        try {
            identities.saveAndFlush(ExternalIdentity.builder().user(user).provider(external.provider())
                    .issuer(external.issuer()).providerSubject(external.subject())
                    .displayName(trim(external.displayName(), 100)).avatar(trim(external.avatar(), 500))
                    .lastAuthenticatedAt(Instant.now()).build());
        } catch (DataIntegrityViolationException race) {
            ExternalIdentity winner = identities.findByProviderAndIssuerAndProviderSubject(
                    external.provider(), external.issuer(), external.subject()).orElseThrow(() -> race);
            return winner.getUser();
        }
        return user;
    }

    private static String normalizeEmail(String value) {
        return StringUtils.hasText(value) ? value.trim().toLowerCase(java.util.Locale.ROOT) : null;
    }

    private static String trim(String value, int limit) {
        if (!StringUtils.hasText(value)) return null;
        String text = value.trim();
        return text.length() <= limit ? text : text.substring(0, limit);
    }
}
