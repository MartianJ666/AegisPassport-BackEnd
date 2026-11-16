package io.aegis.passport.announcement;

import io.aegis.passport.announcement.entity.Announcement;
import io.aegis.passport.audit.Audit;
import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import io.aegis.passport.security.SecurityUtils;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AnnouncementController {

    private final AnnouncementRepository repo;
    private final OAuthClientRepository clientRepo;

    /** Global announcements for authenticated users. */
    @GetMapping("/api/announcements/active")
    public ResponseEntity<ApiResult<List<Announcement>>> active() {
        return ResponseEntity.ok(ApiResult.ok(repo.findActive(Instant.now())));
    }

    @RequirePermission(PermissionCatalog.ANNOUNCEMENT_WRITE)
    @GetMapping("/api/admin/announcements")
    public ResponseEntity<ApiResult<List<Announcement>>> list() {
        return ResponseEntity.ok(ApiResult.ok(repo.findAllByOrderByCreatedAtDesc()));
    }

    @RequirePermission(PermissionCatalog.ANNOUNCEMENT_WRITE)
    @Audit(module = "公告", action = "创建", description = "创建公告")
    @PostMapping("/api/admin/announcements")
    public ResponseEntity<ApiResult<Announcement>> create(@Valid @RequestBody AnnouncementRequest req) {
        Announcement a = new Announcement();
        a.setTitle(req.title); a.setContent(req.content);
        if (req.level != null) a.setLevel(req.level);
        a.setEnabled(req.enabled != null ? req.enabled : true);
        a.setStartTime(req.startTime); a.setEndTime(req.endTime);
        validateTargets(req.targets);
        a.setTargets(req.targets);   // null / empty -> global
        validate(a);
        a.setCreatedBy(SecurityUtils.currentUsername());
        return ResponseEntity.ok(ApiResult.ok(repo.save(a)));
    }

    @RequirePermission(PermissionCatalog.ANNOUNCEMENT_WRITE)
    @Audit(module = "公告", action = "更新", description = "更新公告", targetExpression = "#id")
    @PutMapping("/api/admin/announcements/{id}")
    public ResponseEntity<ApiResult<Announcement>> update(
            @PathVariable Long id, @RequestBody AnnouncementRequest req) {
        Announcement a = repo.findById(id).orElseThrow(() -> BusinessException.of(ErrorCode.NOT_FOUND));
        if (req.title != null) a.setTitle(req.title);
        if (req.content != null) a.setContent(req.content);
        if (req.level != null) a.setLevel(req.level);
        if (req.enabled != null) a.setEnabled(req.enabled);
        // The editor sends the complete time window; null clears an existing bound.
        a.setStartTime(req.startTime);
        a.setEndTime(req.endTime);
        validateTargets(req.targets);
        if (req.targets != null) a.setTargets(req.targets);   // null = keep; [] = clear to global
        validate(a);
        return ResponseEntity.ok(ApiResult.ok(repo.save(a)));
    }

    /** Enabled OAuth clients to pick as announcement targets. */
    @RequirePermission(PermissionCatalog.ANNOUNCEMENT_WRITE)
    @GetMapping("/api/admin/announcements/target-options")
    public ResponseEntity<ApiResult<List<ClientOption>>> targetOptions() {
        List<ClientOption> options = clientRepo.findAllByOrderByCreatedAtDesc().stream()
                .filter(OAuthClient::isEnabled)
                .map(c -> new ClientOption(c.getClientId(), c.getClientName()))
                .toList();
        return ResponseEntity.ok(ApiResult.ok(options));
    }

    public record ClientOption(String clientId, String clientName) {}

    private static void validate(Announcement a) {
        if (a.getTitle() == null || a.getTitle().isBlank() || a.getTitle().length() > 200
                || a.getContent() == null || a.getContent().isBlank() || a.getContent().length() > 20000
                || !java.util.Set.of("info", "success", "warning", "error").contains(a.getLevel())
                || (a.getStartTime() != null && a.getEndTime() != null && a.getEndTime().isBefore(a.getStartTime())))
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "请检查公告标题、内容、级别和有效时间");
    }

    private void validateTargets(List<String> targets) {
        if (targets == null) return;
        if (targets.size() > 50 || targets.stream().anyMatch(t -> t == null || t.isBlank() || t.contains(",")
                || !clientRepo.existsByClientId(t.trim()))
                || String.join(",", targets).length() > 1000)
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "公告目标应用无效");
    }

    @RequirePermission(PermissionCatalog.ANNOUNCEMENT_WRITE)
    @Audit(module = "公告", action = "删除", description = "删除公告", targetExpression = "#id")
    @DeleteMapping("/api/admin/announcements/{id}")
    public ResponseEntity<ApiResult<Void>> delete(@PathVariable Long id) {
        repo.deleteById(id);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @Data
    public static class AnnouncementRequest {
        private String title;
        private String content;
        private String level;
        private Boolean enabled;
        private Instant startTime;
        private Instant endTime;
        /** Target OAuth client ids; null = keep, empty list = global. */
        private List<String> targets;
    }
}
