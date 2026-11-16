package io.aegis.passport.user;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.session.AuthSessionRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

/** Matches the already deployed admin ResetPasswordDialog request contract. */
@RestController
@RequiredArgsConstructor
public class AdminPasswordResetController {
    private final RsaTransportService rsa;
    private final PasswordEncoder encoder;
    private final JdbcTemplate jdbc;
    private final AuthSessionRepository sessions;

    public record ResetRequest(String passwordEncrypted, String confirmPasswordEncrypted) {}

    @PostMapping("/api/user/admin/users/{id}/reset-password")
    @RequirePermission(PermissionCatalog.USER_WRITE)
    @Audit(module="user", action="RESET_PASSWORD", description="管理员重置密码", targetExpression="#id")
    @Transactional
    public ApiResult<Void> reset(@PathVariable Long id, @RequestBody ResetRequest request) {
        String password;
        String confirm;
        try {
            password = rsa.decryptStrict(request.passwordEncrypted());
            confirm = rsa.decryptStrict(request.confirmPasswordEncrypted());
        } catch (IllegalArgumentException ex) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "密码加密数据无效，请刷新页面重试");
        }
        if (!password.equals(confirm) || password.length()<6
                || password.getBytes(StandardCharsets.UTF_8).length>72) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "两次密码需一致，且长度为 6 至 72 字节");
        }
        // Atomic increment, without rewriting any profile/role/enable fields.
        int changed = jdbc.update("UPDATE users SET password=?, credentials_version=credentials_version+1, "
                + "updated_at=? WHERE id=?", encoder.encode(password), java.sql.Timestamp.from(Instant.now()), id);
        if (changed!=1) throw BusinessException.of(ErrorCode.USER_NOT_FOUND);
        sessions.revokeActiveForUserExcept(id, "__none__", Instant.now(),
                "ADMIN_PASSWORD_RESET", SecurityUtils.currentUsername());
        return ApiResult.ok();
    }
}
