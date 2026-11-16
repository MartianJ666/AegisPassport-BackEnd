package io.aegis.passport.audit;

import io.aegis.passport.audit.entity.AuditLog;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    // The distinct-module/action lists and the stats only change as new code
    // ships (module/action strings) or as events land, so short TTLs keep the
    // admin page from re-scanning the whole table on every load — a real source
    // of 503s once the log table grows large.
    private static final long MODULE_ACTION_TTL_MILLIS = 300_000L; // 5 min
    private static final long STATS_TTL_MILLIS = 15_000L;          // 15 s

    private final TtlCache<List<String>> modulesCache = new TtlCache<>(MODULE_ACTION_TTL_MILLIS);
    private final TtlCache<List<String>> actionsCache = new TtlCache<>(MODULE_ACTION_TTL_MILLIS);
    private final TtlCache<Statistics> statsCache = new TtlCache<>(STATS_TTL_MILLIS);

    @Async("auditExecutor")
    public void recordAsync(String module, String action, String description,
                             String operatorName, String targetId, String ip,
                             String path, String method, boolean success,
                             String errorMsg, long elapsedMs) {
        recordAsync(module, action, description, operatorName, targetId, ip,
                path, method, success, errorMsg, elapsedMs, null, null);
    }

    @Async("auditExecutor")
    public void recordAsync(String module, String action, String description,
                             String operatorName, String targetId, String ip,
                             String path, String method, boolean success,
                             String errorMsg, long elapsedMs, String params, String userAgent) {
        try {
            AuditLog entry = AuditLog.builder()
                    .eventId(UUID.randomUUID().toString().replace("-", ""))
                    .module(module).action(action)
                    .description(truncate(description, 255))
                    .operatorName(truncate(operatorName, 100))
                    .targetId(truncate(targetId, 100))
                    // ipAddress/path/method are also attacker-influenced (e.g. a
                    // long X-Forwarded-For first value); truncate to column widths
                    // so an over-long value can never drop the whole audit row.
                    .ipAddress(truncate(ip, 64))
                    .requestPath(truncate(path, 255))
                    .requestMethod(truncate(method, 10))
                    .params(params).userAgent(truncate(userAgent, 500))
                    .success(success).errorMessage(truncate(errorMsg, 500))
                    .executionMs(elapsedMs)
                    .timestamp(Instant.now()).build();
            auditLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("[审计] 记录失败: {}", e.getMessage());
        }
    }

    /**
     * Trim an audit field to its column length so an over-long value (e.g. an
     * untruncated User-Agent from the page-view beacon) can never make save()
     * fail and drop the whole audit row.
     */
    private static String truncate(String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        return value.substring(0, max);
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> search(String module, String action, String operator,
                                  Instant start, Instant end, Boolean success,
                                  Pageable pageable) {
        Specification<AuditLog> spec = (r, q, cb) -> cb.conjunction();
        if (StringUtils.hasText(module))
            spec = spec.and((r, q, cb) -> cb.equal(r.get("module"), module));
        if (StringUtils.hasText(action))
            spec = spec.and((r, q, cb) -> cb.equal(r.get("action"), action));
        if (StringUtils.hasText(operator))
            spec = spec.and((r, q, cb) -> cb.like(r.get("operatorName"), "%" + operator + "%"));
        if (start != null)
            spec = spec.and((r, q, cb) -> cb.greaterThanOrEqualTo(r.get("timestamp"), start));
        if (end != null)
            spec = spec.and((r, q, cb) -> cb.lessThanOrEqualTo(r.get("timestamp"), end));
        if (success != null)
            spec = spec.and((r, q, cb) -> cb.equal(r.get("success"), success));
        return auditLogRepository.findAll(spec, pageable);
    }

    @Transactional(readOnly = true)
    public List<String> modules() {
        return modulesCache.get(auditLogRepository::findDistinctModules);
    }

    @Transactional(readOnly = true)
    public List<String> actions() {
        return actionsCache.get(auditLogRepository::findDistinctActions);
    }

    @Transactional
    public void archiveBefore(Instant cutoff) {
        // Bulk DELETE instead of load-all-then-deleteAll: on the (large) audit table
        // the old approach pulled every matching row into the persistence context —
        // a multi-GB heap spike / long transaction that could OOM the container.
        auditLogRepository.deleteByTimestampBefore(cutoff);
        // The deletion changes every derived query — drop the short-TTL caches.
        modulesCache.clear();
        actionsCache.clear();
        statsCache.clear();
    }

    public record Statistics(long total, long succeeded, long failed, long last24h) {}

    @Transactional(readOnly = true)
    public Statistics statistics(Instant start, Instant end) {
        // start/end are accepted for future filter support; today the cards show
        // all-time totals + last-24h. Cached for 15 s so a page reload doesn't
        // re-scan the whole table four times.
        return statsCache.get(() -> {
            long total = auditLogRepository.count();
            long ok = auditLogRepository.countBySuccess(true);
            long failed = auditLogRepository.countBySuccess(false);
            long last24h = auditLogRepository.countByTimestampAfter(Instant.now().minusSeconds(86400));
            return new Statistics(total, ok, failed, last24h);
        });
    }

    /**
     * Tiny single-value cache with a time-to-live. Single-instance app today, so
     * an in-process holder is sufficient; a multi-instance deployment would use
     * the shared {@code CacheManager} instead.
     */
    private static final class TtlCache<T> {

        private final long ttlMillis;
        private volatile T value;
        private volatile long expiresAt;

        TtlCache(long ttlMillis) {
            this.ttlMillis = ttlMillis;
        }

        synchronized T get(Supplier<T> loader) {
            long now = System.currentTimeMillis();
            if (value != null && now < expiresAt) {
                return value;
            }
            value = loader.get();
            expiresAt = System.currentTimeMillis() + ttlMillis;
            return value;
        }

        synchronized void clear() {
            value = null;
            expiresAt = 0L;
        }
    }
}
