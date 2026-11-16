package io.aegis.passport.consent;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.SecurityUtils;
import java.util.List;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Authorized-application management. Gated on {@code consent:read}: only roles
 * that may hold OAuth authorizations (member and above) can list, save, or
 * revoke consents. A plain {@code user} has no OAuth-app capability, so these
 * endpoints reject them (and the rejection is recorded as a security violation).
 */
@RestController
@RequestMapping("/api/user/consents")
@RequiredArgsConstructor
@RequirePermission(PermissionCatalog.CONSENT_READ)
public class ConsentController {

    private final ConsentService consentService;

    @GetMapping
    public ResponseEntity<ApiResult<List<ConsentService.ConsentView>>> list() {
        return ResponseEntity.ok(ApiResult.ok(
                consentService.listByUser(SecurityUtils.currentUsername())));
    }

    @Audit(module = "授权管理", action = "保存授权", description = "保存应用授权")
    @PostMapping("/save")
    public ResponseEntity<ApiResult<Void>> save(@RequestBody SaveRequest req) {
        consentService.save(req.clientId, SecurityUtils.currentUsername(),
                req.scopes, Boolean.TRUE.equals(req.remember));
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Audit(module = "授权管理", action = "撤销授权", description = "撤销单条应用授权", targetExpression = "#id")
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResult<Void>> revoke(@PathVariable Long id) {
        consentService.revoke(id, SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Audit(module = "授权管理", action = "撤销客户端授权", description = "撤销客户端的全部授权", targetExpression = "#clientId")
    @DeleteMapping("/client/{clientId}")
    public ResponseEntity<ApiResult<Void>> revokeByClient(@PathVariable String clientId) {
        consentService.revokeByClient(clientId, SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Data
    public static class SaveRequest {
        private String clientId;
        private List<String> scopes;
        private Boolean remember;
    }
}
