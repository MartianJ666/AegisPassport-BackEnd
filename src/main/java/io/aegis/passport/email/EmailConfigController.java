package io.aegis.passport.email;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.email.entity.EmailConfig;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.rbac.PermissionCatalog;
import jakarta.validation.Valid;
import java.util.Optional;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/email-config")
@RequiredArgsConstructor
public class EmailConfigController {

    private final EmailConfigRepository configRepo;
    private final EmailService emailService;

    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_VIEW)
    @GetMapping
    public ResponseEntity<ApiResult<ConfigView>> get() {
        return configRepo.findTopByOrderByIdAsc()
                .map(cfg -> ResponseEntity.ok(ApiResult.ok(ConfigView.from(cfg))))
                .orElse(ResponseEntity.ok(ApiResult.ok(null)));
    }

    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
    @PostMapping
    public ResponseEntity<ApiResult<ConfigView>> save(@Valid @RequestBody SaveRequest req) {
        EmailConfig cfg = configRepo.findTopByOrderByIdAsc().orElse(new EmailConfig());
        cfg.setSmtpHost(req.smtpHost);
        cfg.setSmtpPort(req.smtpPort);
        cfg.setSmtpUsername(req.smtpUsername);
        if (req.smtpPassword != null && !req.smtpPassword.isBlank()) cfg.setSmtpPassword(req.smtpPassword);
        cfg.setFromEmail(req.fromEmail);
        cfg.setFromName(req.fromName);
        cfg.setUseSsl(req.useSsl != null && req.useSsl);
        cfg.setUseTls(req.useTls == null || req.useTls);
        cfg.setEnabled(req.enabled != null && req.enabled);
        configRepo.save(cfg);
        return ResponseEntity.ok(ApiResult.ok(ConfigView.from(cfg)));
    }

    @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
    @PostMapping("/test")
    public ResponseEntity<ApiResult<Void>> test(@RequestParam String email) {
        if (!emailService.isEnabled()) throw BusinessException.of(ErrorCode.EMAIL_NOT_CONFIGURED);
        emailService.sendTest(email);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Data
    public static class SaveRequest {
        private String smtpHost;
        private Integer smtpPort;
        private String smtpUsername;
        private String smtpPassword;
        private String fromEmail;
        private String fromName;
        private Boolean useSsl;
        private Boolean useTls;
        private Boolean enabled;
    }

    public record ConfigView(Long id, String smtpHost, Integer smtpPort, String smtpUsername,
                              String fromEmail, String fromName, boolean useSsl, boolean useTls, boolean enabled) {
        static ConfigView from(EmailConfig c) {
            return new ConfigView(c.getId(), c.getSmtpHost(), c.getSmtpPort(), c.getSmtpUsername(),
                    c.getFromEmail(), c.getFromName(), c.isUseSsl(), c.isUseTls(), c.isEnabled());
        }
    }
}
