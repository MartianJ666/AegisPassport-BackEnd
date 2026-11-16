package io.aegis.passport.user;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.auth.dto.AuthDtos.ChangePasswordRequest;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.api.PageResult;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.security.SecurityViolationService;
import io.aegis.passport.user.dto.UserDtos.*;
import io.aegis.passport.external.ExternalLoginService;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import jakarta.validation.Valid;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final io.aegis.passport.session.SessionService sessionService;
    private final PasswordEncoder passwordEncoder;
    private final RsaTransportService rsa;
    private final SecurityViolationService violationService;
    private final ExternalLoginService externalLoginService;

    @GetMapping("/profile")
    @Audit(module = "user", action = "VIEW_PROFILE", description = "查看个人资料")
    public ResponseEntity<ApiResult<UserView>> profile() {
        return ResponseEntity.ok(ApiResult.ok(userService.getByUsername(SecurityUtils.currentUsername())));
    }

    @PutMapping("/profile")
    @Audit(module = "user", action = "UPDATE_PROFILE", description = "修改个人资料")
    public ResponseEntity<ApiResult<UserView>> updateProfile(@Valid @RequestBody UpdateProfileRequest req) {
        return ResponseEntity.ok(ApiResult.ok(userService.updateProfile(SecurityUtils.currentUsername(), req)));
    }


    @PutMapping("/username")
    @Audit(module = "user", action = "CHANGE_USERNAME", description = "修改用户名")
    public ResponseEntity<ApiResult<Map<String, String>>> changeUsername(
            @RequestBody ChangeUsernameRequest req, HttpServletRequest request, HttpServletResponse response) {
        User user = userService.changeUsername(SecurityUtils.currentUsername(), req.getUsername());
        String token = externalLoginService.reissue(user, request, response);
        return ResponseEntity.ok(ApiResult.ok(Map.of("token", token)));
    }

    @PostMapping("/change-password")
    @Audit(module = "user", action = "CHANGE_PASSWORD", description = "修改登录密码")
    public ResponseEntity<ApiResult<Void>> changePassword(@Valid @RequestBody ChangePasswordRequest req, jakarta.servlet.http.HttpServletRequest request) {
        req.setOldPassword(rsa.decrypt(req.getOldPassword()));
        req.setNewPassword(rsa.decrypt(req.getNewPassword()));
        userService.changePassword(SecurityUtils.currentUsername(), req);
        sessionService.revokeOtherSessions(SecurityUtils.currentUserId(), io.aegis.passport.session.SessionService.sessionId(request), SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    // ── Admin endpoints ────────────────────────────────────────────────────

    @GetMapping("/admin/users")
    @RequirePermission(PermissionCatalog.USER_READ)
    @Audit(module = "user", action = "VIEW_USERS", description = "查看用户列表")
    public ResponseEntity<ApiResult<PageResult<UserView>>> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String dir) {
        if (!Set.of("id", "username", "nickname", "email", "createdAt", "updatedAt", "lastLoginAt").contains(sortBy))
            throw new IllegalArgumentException("不支持的排序字段");
        size = Math.max(1, Math.min(200, size)); page = Math.max(0, page);
        Sort sort = "asc".equalsIgnoreCase(dir) ? Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        return ResponseEntity.ok(ApiResult.ok(PageResult.of(
                userService.getUserRepository().findAll(PageRequest.of(page, size, sort)).map(UserView::from))));
    }

    @GetMapping("/admin/users/search")
    @RequirePermission(PermissionCatalog.USER_READ)
    public ResponseEntity<ApiResult<PageResult<UserView>>> searchUsers(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        size = Math.max(1, Math.min(200, size)); page = Math.max(0, page);
        return ResponseEntity.ok(ApiResult.ok(PageResult.of(
                userService.getUserRepository().search(keyword, PageRequest.of(page, size, Sort.by("createdAt").descending()))
                        .map(UserView::from))));
    }

    @PutMapping("/admin/users/{id}")
    @RequirePermission(PermissionCatalog.USER_WRITE)
    @Audit(module = "user", action = "UPDATE_USER", description = "编辑用户", targetExpression = "#id")
    public ResponseEntity<ApiResult<UserView>> updateUser(@PathVariable Long id, @RequestBody AdminUpdateUserRequest req) {
        return ResponseEntity.ok(ApiResult.ok(userService.adminUpdateUser(id, req, passwordEncoder)));
    }

    @DeleteMapping("/admin/users/{id}")
    @RequirePermission(PermissionCatalog.USER_DELETE)
    @Audit(module = "user", action = "DELETE_USER", description = "删除用户", targetExpression = "#id")
    public ResponseEntity<ApiResult<Void>> deleteUser(@PathVariable Long id) {
        userService.batchDelete(java.util.List.of(id), SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/admin/users/batch/enable")
    @RequirePermission(PermissionCatalog.USER_WRITE)
    @Audit(module = "user", action = "BATCH_ENABLE", description = "批量启用/禁用用户")
    public ResponseEntity<ApiResult<Integer>> batchEnable(@RequestBody BatchEnableRequest req) {
        return ResponseEntity.ok(ApiResult.ok(userService.batchSetEnabled(req.getUserIds(), req.isEnabled())));
    }

    @PostMapping("/admin/users/batch/roles")
    @RequirePermission(PermissionCatalog.USER_WRITE)
    @Audit(module = "user", action = "BATCH_ASSIGN_ROLE", description = "批量分配角色")
    public ResponseEntity<ApiResult<Void>> batchAssignRole(@RequestBody BatchRoleRequest req) {
        for (Long id : req.getUserIds()) {
            userService.assignRoles(id, Set.of(req.getRoleCode()));
        }
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/admin/users/batch/delete")
    @RequirePermission(PermissionCatalog.USER_DELETE)
    @Audit(module = "user", action = "BATCH_DELETE", description = "批量删除用户")
    public ResponseEntity<ApiResult<Void>> batchDelete(@RequestBody BatchDeleteRequest req) {
        userService.batchDelete(req.getUserIds(), SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/admin/users/{id}/roles")
    @RequirePermission(PermissionCatalog.USER_WRITE)
    @Audit(module = "user", action = "ASSIGN_ROLE", description = "分配角色", targetExpression = "#id")
    public ResponseEntity<ApiResult<Void>> assignRoles(@PathVariable Long id, @RequestBody Set<String> roleCodes) {
        userService.assignRoles(id, roleCodes);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/admin/users/{id}/ban")
    @RequirePermission(PermissionCatalog.USER_BAN)
    @Audit(module = "user", action = "BAN_USER", description = "封禁/解封用户", targetExpression = "#id")
    public ResponseEntity<ApiResult<Void>> banUser(@PathVariable Long id, @RequestBody BanUserRequest req) {
        violationService.setBan(id, req.isBan(), req.getDurationHours());
        return ResponseEntity.ok(ApiResult.ok());
    }
}
