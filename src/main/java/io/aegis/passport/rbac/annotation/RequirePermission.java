package io.aegis.passport.rbac.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the authenticated principal to hold one (default) or all of the
 * listed permission codes. Enforced centrally by {@code AuthorizationAspect},
 * which resolves the caller's effective permissions (roles + direct grants)
 * and throws a {@code ForbiddenException} → clean 403 on failure.
 *
 * <p>This single annotation replaces the original mix of {@code @PreAuthorize},
 * manual {@code isAdmin()} string checks, and a separate annotation path.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {

    /** Permission codes from {@code PermissionCatalog}. */
    String[] value();

    /** When true, every listed permission is required; otherwise any one. */
    boolean requireAll() default false;
}
