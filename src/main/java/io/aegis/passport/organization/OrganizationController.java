package io.aegis.passport.organization;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/organizations") @RequiredArgsConstructor
public class OrganizationController {
    private final OrganizationService service;
    public record Edit(@NotBlank @Size(max=100) String name,@Size(max=255) String description) {}
    public record Membership(boolean member) {}
    @GetMapping @RequirePermission({PermissionCatalog.ORGANIZATION_READ,PermissionCatalog.USER_WRITE,PermissionCatalog.CLIENT_WRITE})
    public Object list(){return ApiResult.ok(service.list());}
    @PostMapping @RequirePermission(PermissionCatalog.ORGANIZATION_WRITE)
    @Audit(module="organization",action="CREATE_ORGANIZATION",description="新建组织")
    public Object create(@Valid @RequestBody Edit req){return ApiResult.ok(service.save(null,req.name(),req.description()));}
    @PutMapping("/{id}") @RequirePermission(PermissionCatalog.ORGANIZATION_WRITE)
    @Audit(module="organization",action="UPDATE_ORGANIZATION",description="编辑组织")
    public Object update(@PathVariable Long id,@Valid @RequestBody Edit req){return ApiResult.ok(service.save(id,req.name(),req.description()));}
    @DeleteMapping("/{id}") @RequirePermission(PermissionCatalog.ORGANIZATION_WRITE)
    @Audit(module="organization",action="DELETE_ORGANIZATION",description="删除空组织")
    public Object delete(@PathVariable Long id){service.delete(id);return ApiResult.ok();}
    @GetMapping("/{id}/members") @RequirePermission(value={PermissionCatalog.ORGANIZATION_READ,PermissionCatalog.USER_READ},requireAll=true)
    public Object members(@PathVariable Long id){return ApiResult.ok(service.members(id));}
    @PutMapping("/{id}/members/{userId}") @RequirePermission(value={PermissionCatalog.ORGANIZATION_WRITE,PermissionCatalog.USER_WRITE},requireAll=true)
    @Audit(module="organization",action="ASSIGN_ORGANIZATION",description="调整组织成员")
    public Object member(@PathVariable Long id,@PathVariable Long userId,@RequestBody Membership req){service.setMember(id,userId,req.member());return ApiResult.ok();}
    @GetMapping("/{id}/apps") @RequirePermission(value={PermissionCatalog.ORGANIZATION_READ,PermissionCatalog.CLIENT_READ},requireAll=true)
    public Object apps(@PathVariable Long id){return ApiResult.ok(service.apps(id));}
    @PutMapping("/{id}/apps") @RequirePermission(value={PermissionCatalog.ORGANIZATION_WRITE,PermissionCatalog.CLIENT_WRITE},requireAll=true)
    @Audit(module="organization",action="ORGANIZATION_APP_ACCESS",description="调整组织应用门禁")
    public Object apps(@PathVariable Long id,@RequestBody Map<String,Boolean> req){service.setApps(id,req);return ApiResult.ok();}
}
