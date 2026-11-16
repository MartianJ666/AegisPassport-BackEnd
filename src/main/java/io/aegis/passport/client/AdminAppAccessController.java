package io.aegis.passport.client;
import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.annotation.RequireRole;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/admin/users/{userId}/app-access") @RequireRole("admin") @RequiredArgsConstructor
public class AdminAppAccessController {
 private final AdminAppAccessService service;
 @GetMapping public Object list(@PathVariable Long userId){return ApiResult.ok(service.list(userId));}
 @PutMapping("/{clientId}")
 @Audit(module="client",action="ADMIN_APP_ACCESS",description="管理员应用特批或撤销",targetExpression="#userId")
 public Object set(@PathVariable Long userId,@PathVariable String clientId,@RequestParam String mode,@RequestParam(required=false) Integer hours){return ApiResult.ok(service.set(userId,clientId,mode,hours));}
}
