package io.aegis.passport.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller method for automatic audit logging. The
 * {@link AuditAspect} records the caller, timing, outcome and optional
 * parameter snapshot asynchronously so the request thread is not blocked.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audit {

    String module() default "";
    String action() default "";
    String description() default "";
    /** SpEL expression resolving the target entity id, e.g. {@code "#id"}. */
    String targetExpression() default "";
}
