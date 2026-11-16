package io.aegis.passport.security;
import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.time.Instant;
import lombok.RequiredArgsConstructor; import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service; import org.springframework.transaction.annotation.Transactional;
/**
 * Records over-permission access attempts to the audit log and surfaces them in
 * the admin console. By design it does NOT auto-ban: a violation increments a
 * counter and writes a "越权访问" audit entry, but locking an account is a
 * deliberate admin action via {@link #setBan}. This avoids a stray API call or
 * a misconfigured client locking out a legitimate user.
 */
@Slf4j @Service @RequiredArgsConstructor
public class SecurityViolationService {
    /** Sentinel for a permanent (no-expiry) ban stored in banned_until. */
    private static final Instant PERMANENT_BAN = Instant.parse("2999-12-31T23:59:59Z");
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    @Async @Transactional
    public void recordViolation(Long userId, String username, String path, String method, String ip) {
        if (userId == null) return;
        userRepository.incrementViolationCount(userId);
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) return;
        // incrementViolationCount already incremented the stored value, so the
        // reloaded count IS this attempt's ordinal (no "+1" here).
        int count = user.getViolationCount();
        auditLogService.recordAsync("安全审计", "越权访问", "用户越权访问被拒绝 (第" + count + "次)", username, null, ip, path, method != null ? method : "unknown", false, "越权访问 - 权限不足", 0);
        log.warn("[安全] 用户 {} ({}) 越权访问 {} {} - 第{}次", username, userId, method, path, count);
    }
    @Transactional
    public void setBan(Long userId, boolean ban, int durationHours) {
        if (ban) {
            Instant bannedUntil = durationHours > 0 ? Instant.now().plusSeconds(durationHours * 3600L) : PERMANENT_BAN;
            userRepository.setBanStatus(userId, 0, bannedUntil);
            auditLogService.recordAsync("安全审计", "封禁账户", durationHours > 0 ? "管理员封禁账户" + durationHours + "小时" : "管理员永久封禁账户", null, String.valueOf(userId), null, null, "SYSTEM", true, null, 0);
        } else {
            userRepository.setBanStatus(userId, 0, null);
            auditLogService.recordAsync("安全审计", "解封账户", "管理员解封账户", null, String.valueOf(userId), null, null, "SYSTEM", true, null, 0);
        }
        log.info("[封禁] {} 用户 {} {}", ban ? "封禁" : "解封", userId, durationHours > 0 ? durationHours + "小时" : "");
    }
    @Scheduled(fixedRate = 300_000)
    @Transactional
    public void liftExpiredBans() {
        java.util.List<User> expired = userRepository.findExpiredBans(Instant.now());
        for (User user : expired) {
            user.setBannedUntil(null); user.setViolationCount(0);
            userRepository.save(user);
            log.info("[封禁] 用户 {} 定时封禁已到期，自动解封", user.getUsername());
        }
    }
}
