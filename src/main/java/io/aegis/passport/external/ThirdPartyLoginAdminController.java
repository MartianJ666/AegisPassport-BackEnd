package io.aegis.passport.external;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/third-party-login")
@RequiredArgsConstructor
@RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
public class ThirdPartyLoginAdminController {
    private final ThirdPartyLoginConfigService service;

    @GetMapping
    public ResponseEntity<ApiResult<ThirdPartyLoginConfigService.AdminView>> get() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Pragma", "no-cache")
                .body(ApiResult.ok(service.adminView()));
    }

    @PutMapping
    @Audit(module = "system", action = "THIRD_PARTY_LOGIN_CONFIG_SAVE", description = "保存第三方登录配置")
    public ResponseEntity<ApiResult<ThirdPartyLoginConfigService.AdminView>> save(
            @RequestBody ThirdPartyLoginConfigService.SaveRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Pragma", "no-cache")
                .body(ApiResult.ok(service.save(request)));
    }
}
