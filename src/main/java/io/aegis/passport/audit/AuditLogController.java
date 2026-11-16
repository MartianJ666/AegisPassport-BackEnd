package io.aegis.passport.audit;

import io.aegis.passport.audit.entity.AuditLog;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.api.PageResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/audit-logs")
@RequiredArgsConstructor
@RequirePermission(PermissionCatalog.AUDIT_READ)
public class AuditLogController {

    private final AuditLogService service;

    @GetMapping
    public ResponseEntity<ApiResult<PageResult<AuditLog>>> list(
            @RequestParam(required = false) String module,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String operator,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant end,
            @RequestParam(required = false) Boolean success,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        // Clamp instead of trusting the client: page<0 or size<1 would make
        // PageRequest.of throw and surface as a 400; a huge size would run a
        // giant query and trip the proxy timeout (503).
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 200);
        Page<AuditLog> result = service.search(module, action, operator, start, end, success,
                PageRequest.of(safePage, safeSize, Sort.by("timestamp").descending()));
        return ResponseEntity.ok(ApiResult.ok(PageResult.of(result)));
    }

    @GetMapping("/modules")
    public ResponseEntity<ApiResult<List<String>>> modules() {
        return ResponseEntity.ok(ApiResult.ok(service.modules()));
    }

    @GetMapping("/actions")
    public ResponseEntity<ApiResult<List<String>>> actions() {
        return ResponseEntity.ok(ApiResult.ok(service.actions()));
    }

    @GetMapping("/statistics")
    public ResponseEntity<ApiResult<AuditLogService.Statistics>> statistics(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant end) {
        return ResponseEntity.ok(ApiResult.ok(service.statistics(start, end)));
    }

    @GetMapping("/export")
    public void export(
            @RequestParam(required = false) String module,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String operator,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant end,
            @RequestParam(required = false) Boolean success,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=audit_logs.csv");
        response.getOutputStream().write(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF});
        String header = "时间,模块,操作,操作人,目标,IP地址,User-Agent,路径,方法,耗时ms,结果,错误,请求参数\n";
        response.getOutputStream().write(header.getBytes(StandardCharsets.UTF_8));
        Page<AuditLog> data = service.search(module, action, operator, start, end, success,
                PageRequest.of(0, 10000, Sort.by("timestamp").descending()));
        for (AuditLog a : data.getContent()) {
            String line = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s\n",
                    esc(a.getTimestamp() != null ? a.getTimestamp().toString() : ""),
                    esc(a.getModule()), esc(a.getAction()), esc(a.getOperatorName()),
                    esc(a.getTargetId()), esc(a.getIpAddress()), esc(a.getUserAgent()),
                    esc(a.getRequestPath()), esc(a.getRequestMethod()),
                    a.getExecutionMs() != null ? a.getExecutionMs() : 0,
                    a.isSuccess() ? "成功" : "失败", esc(a.getErrorMessage()), esc(a.getParams()));
            response.getOutputStream().write(line.getBytes(StandardCharsets.UTF_8));
        }
    }

    @PostMapping("/archive")
    public ResponseEntity<ApiResult<Void>> archive(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant before) {
        service.archiveBefore(before);
        return ResponseEntity.ok(ApiResult.ok());
    }

    private String esc(String v) {
        if (v == null) return "";
        String s = v;
        // Excel formula injection: a cell beginning with =, +, -, @ is executed as
        // a formula when the CSV is opened in a spreadsheet. Neutralize the leading
        // character with a single quote (the OWASP CSV-injection mitigation).
        if (s.startsWith("=") || s.startsWith("+") || s.startsWith("-") || s.startsWith("@")) {
            s = "'" + s;
        }
        if (s.contains(",") || s.contains("\n") || s.contains("\""))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }
}
