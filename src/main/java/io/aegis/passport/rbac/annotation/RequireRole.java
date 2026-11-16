package io.aegis.passport.rbac.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the authenticated principal to hold one of the listed role codes.
 * Enforced by {@code AuthorizationAspect}. Prefer {@link RequirePermission} for
 * capability checks; use this only when the gate is genuinely role-shaped.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {

    String[] value();
}
