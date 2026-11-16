package io.aegis.passport.security;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Convenience accessors for the current {@link PassportUserPrincipal}. */
public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static Optional<PassportUserPrincipal> currentPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof PassportUserPrincipal p) {
            return Optional.of(p);
        }
        return Optional.empty();
    }

    /** Current user id, or throw 401 if unauthenticated. */
    public static Long currentUserId() {
        return currentPrincipal()
                .map(PassportUserPrincipal::getId)
                .orElseThrow(() -> BusinessException.of(ErrorCode.UNAUTHORIZED));
    }

    public static String currentUsername() {
        return currentPrincipal()
                .map(PassportUserPrincipal::getUsername)
                .orElse(null);
    }
}
