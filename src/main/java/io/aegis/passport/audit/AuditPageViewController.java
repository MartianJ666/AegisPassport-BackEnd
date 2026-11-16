package io.aegis.passport.audit;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.security.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Records authenticated SPA page views so the audit trail answers "who looked at
 * what page, when, from which IP". The Vue router beacons after each navigation.
 * Kept intentionally lightweight and best-effort — a failed beacon never blocks
 * navigation.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditPageViewController {

    private final AuditLogService auditLogService;

    @PostMapping("/page-view")
    public ResponseEntity<ApiResult<Void>> pageView(@RequestBody PageViewRequest body,
                                                    HttpServletRequest request) {
        String operator = SecurityUtils.currentUsername();
        String xff = request.getHeader("X-Forwarded-For");
        String ip = xff != null && !xff.isBlank() ? xff.split(",")[0].trim() : request.getRemoteAddr();
        auditLogService.recordAsync(
                "page", "VIEW", body.getPage() != null ? body.getPage() : (body.getPath() != null ? body.getPath() : "/"),
                operator, null, ip, "/api/audit/page-view", "POST",
                true, null, 0L, null, request.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Data
    public static class PageViewRequest {
        private String page;
        private String path;
    }
}
