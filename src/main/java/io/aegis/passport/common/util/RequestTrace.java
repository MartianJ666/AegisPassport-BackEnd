package io.aegis.passport.common.util;

import java.util.UUID;

/**
 * Per-request correlation id, stored in a thread-local and echoed in every
 * {@link io.aegis.passport.common.api.ApiResult}. Populated by
 * {@code TraceFilter} at the edge of the request.
 */
public final class RequestTrace {

    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private RequestTrace() {
    }

    public static String start(String incoming) {
        String id = (incoming == null || incoming.isBlank()) ? newId() : incoming;
        HOLDER.set(id);
        return id;
    }

    public static String current() {
        String id = HOLDER.get();
        return id != null ? id : "-";
    }

    public static String newId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    public static void clear() {
        HOLDER.remove();
    }
}
