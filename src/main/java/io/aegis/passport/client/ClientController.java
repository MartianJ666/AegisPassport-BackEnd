package io.aegis.passport.client;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.SecurityUtils;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final OAuthClientService clientService;

    private boolean isAdmin(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    @RequirePermission(PermissionCatalog.CLIENT_READ)
    @GetMapping
    public ResponseEntity<ApiResult<List<OAuthClient>>> list(Authentication auth) {
        return ResponseEntity.ok(ApiResult.ok(
                clientService.getClientsForUser(SecurityUtils.currentUsername(), isAdmin(auth))));
    }

    @RequirePermission(PermissionCatalog.CLIENT_WRITE)
    @Audit(module = "应用管理", action = "创建应用", description = "创建 OAuth 应用")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResult<OAuthClient>> create(
            @RequestPart("data") OAuthClientService.ClientRequest req,
            @RequestPart(value = "icon", required = false) MultipartFile icon,
            Authentication auth) throws Exception {
        return ResponseEntity.ok(ApiResult.ok(
                clientService.create(req, icon, SecurityUtils.currentUsername(), isAdmin(auth))));
    }

    @RequirePermission(PermissionCatalog.CLIENT_WRITE)
    @Audit(module = "应用管理", action = "更新应用", description = "更新 OAuth 应用", targetExpression = "#clientId")
    @PutMapping(value = "/{clientId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResult<OAuthClient>> update(
            @PathVariable String clientId,
            @RequestPart("data") OAuthClientService.ClientRequest req,
            @RequestPart(value = "icon", required = false) MultipartFile icon,
            Authentication auth) throws Exception {
        return ResponseEntity.ok(ApiResult.ok(
                clientService.update(clientId, req, icon, SecurityUtils.currentUsername(), isAdmin(auth))));
    }

    @RequirePermission(PermissionCatalog.CLIENT_DELETE)
    @Audit(module = "应用管理", action = "删除应用", description = "删除 OAuth 应用", targetExpression = "#clientId")
    @DeleteMapping("/{clientId}")
    public ResponseEntity<ApiResult<Void>> delete(
            @PathVariable String clientId, Authentication auth) {
        clientService.delete(clientId, SecurityUtils.currentUsername(), isAdmin(auth));
        return ResponseEntity.ok(ApiResult.ok());
    }
}
