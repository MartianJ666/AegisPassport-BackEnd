package io.aegis.passport.apikey;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.SecurityUtils;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Map;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ApiKeyController {

    private final ApiKeyService service;

    // ── User endpoints ─────────────────────────────────────────────────────

    @PostMapping("/api/api-keys")
    @RequirePermission(PermissionCatalog.APIKEY_READ)
    @Audit(module = "API密钥", action = "创建", description = "创建 API 密钥")
    public ResponseEntity<ApiResult<Map<String, Object>>> create(
            @Valid @RequestBody CreateRequest req) {
        return ResponseEntity.ok(ApiResult.ok(
                service.create(SecurityUtils.currentUsername(), req.name,
                        req.scopes, req.expiresAt)));
    }

    @GetMapping("/api/api-keys/my")
    @RequirePermission(PermissionCatalog.APIKEY_READ)
    public ResponseEntity<ApiResult<?>> listMine() {
        return ResponseEntity.ok(ApiResult.ok(service.listMine(SecurityUtils.currentUsername())));
    }

    @DeleteMapping("/api/api-keys/my/{id}")
    @RequirePermission(PermissionCatalog.APIKEY_READ)
    @Audit(module = "API密钥", action = "删除", description = "删除 API 密钥", targetExpression = "#id")
    public ResponseEntity<ApiResult<Void>> deleteMine(@PathVariable Long id) {
        service.deleteMine(id, SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PatchMapping("/api/api-keys/my/{id}/toggle")
    @RequirePermission(PermissionCatalog.APIKEY_READ)
    public ResponseEntity<ApiResult<?>> toggleMine(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResult.ok(service.toggleMine(id, SecurityUtils.currentUsername())));
    }

    // ── Admin endpoints ────────────────────────────────────────────────────

    @RequirePermission(PermissionCatalog.APIKEY_ADMIN)
    @GetMapping("/api/admin/api-keys")
    public ResponseEntity<ApiResult<?>> listAll() {
        return ResponseEntity.ok(ApiResult.ok(service.listAll()));
    }

    @RequirePermission(PermissionCatalog.APIKEY_ADMIN)
    @DeleteMapping("/api/admin/api-keys/{id}")
    public ResponseEntity<ApiResult<Void>> deleteById(@PathVariable Long id) {
        service.deleteById(id);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @RequirePermission(PermissionCatalog.APIKEY_ADMIN)
    @PatchMapping("/api/admin/api-keys/{id}/toggle")
    public ResponseEntity<ApiResult<?>> toggleAdmin(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResult.ok(service.toggleAdmin(id)));
    }

    // ── Public verify ──────────────────────────────────────────────────────

    @PostMapping("/api/public/api-keys/verify")
    public ResponseEntity<ApiResult<Map<String, Object>>> verify(
            @RequestBody VerifyRequest req) {
        return ResponseEntity.ok(ApiResult.ok(service.verify(req.apiKey, req.apiSecret)));
    }

    @Data
    public static class CreateRequest {
        @NotBlank private String name;
        private String scopes;
        private Instant expiresAt;
    }

    @Data
    public static class VerifyRequest {
        private String apiKey;
        private String apiSecret;
    }
}
