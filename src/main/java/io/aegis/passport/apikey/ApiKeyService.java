package io.aegis.passport.apikey;

import io.aegis.passport.apikey.entity.ApiKey;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private final ApiKeyRepository repo;
    private final UserRepository userRepo;
    private final BCryptPasswordEncoder secretEncoder = new BCryptPasswordEncoder();
    private final SecureRandom random = new SecureRandom();

    @Transactional
    public Map<String, Object> create(String username, String name, String scopes, Instant expiresAt) {
        User owner = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        byte[] keyBytes = new byte[24];
        random.nextBytes(keyBytes);
        String rawKey = "ak_" + Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);
        byte[] secBytes = new byte[32];
        random.nextBytes(secBytes);
        String rawSecret = "as_" + Base64.getUrlEncoder().withoutPadding().encodeToString(secBytes);
        ApiKey key = ApiKey.builder()
                .name(name).apiKey(rawKey).apiSecret(secretEncoder.encode(rawSecret))
                .scopes(scopes).enabled(true).expiresAt(expiresAt).owner(owner).build();
        repo.save(key);
        // Secret shown only once
        return Map.of("id", key.getId(), "apiKey", rawKey, "apiSecret", rawSecret,
                "name", name, "createdAt", key.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public List<ApiKeyView> listMine(String username) {
        User owner = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        return repo.findByOwnerIdOrderByCreatedAtDesc(owner.getId()).stream().map(ApiKeyView::from).toList();
    }

    @Transactional
    public void deleteMine(Long id, String username) {
        User owner = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        ApiKey key = repo.findByIdAndOwnerId(id, owner.getId())
                .orElseThrow(() -> BusinessException.of(ErrorCode.API_KEY_NOT_FOUND));
        repo.delete(key);
    }

    @Transactional
    public ApiKeyView toggleMine(Long id, String username) {
        User owner = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        ApiKey key = repo.findByIdAndOwnerId(id, owner.getId())
                .orElseThrow(() -> BusinessException.of(ErrorCode.API_KEY_NOT_FOUND));
        key.setEnabled(!key.isEnabled());
        return ApiKeyView.from(repo.save(key));
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<ApiKeyView> listAll() { return repo.findAllByOrderByCreatedAtDesc().stream().map(ApiKeyView::from).toList(); }

    @Transactional
    public void deleteById(Long id) {
        repo.delete(repo.findById(id)
                .orElseThrow(() -> BusinessException.of(ErrorCode.API_KEY_NOT_FOUND)));
    }

    @Transactional
    public ApiKeyView toggleAdmin(Long id) {
        ApiKey key = repo.findById(id)
                .orElseThrow(() -> BusinessException.of(ErrorCode.API_KEY_NOT_FOUND));
        key.setAdminDisabled(!key.isAdminDisabled());
        return ApiKeyView.from(repo.save(key));
    }

    // ── Public verification ───────────────────────────────────────────────────

    @Transactional
    public Map<String, Object> verify(String rawKey, String rawSecret) {
        ApiKey key = repo.findByApiKey(rawKey).orElse(null);
        if (key == null || !key.isEnabled() || key.isAdminDisabled()) {
            return Map.of("valid", false, "message", "密钥无效或已禁用");
        }
        User owner = key.getOwner();
        if (owner == null || !owner.isEnabled() || owner.isLocked() || owner.isBanned() || owner.isNeedsSetup()) {
            return Map.of("valid", false, "message", "密钥所属账号不可用");
        }
        if (key.getExpiresAt() != null && Instant.now().isAfter(key.getExpiresAt())) {
            return Map.of("valid", false, "message", "密钥已过期");
        }
        if (!secretEncoder.matches(rawSecret, key.getApiSecret())) {
            return Map.of("valid", false, "message", "密钥验证失败");
        }
        key.setLastUsedAt(Instant.now());
        key.setUseCount(key.getUseCount() + 1);
        repo.save(key);
        return Map.of("valid", true, "message", "验证成功",
                "userId", key.getOwner().getId(),
                "username", key.getOwner().getUsername(),
                "scopes", key.getScopes() != null ? key.getScopes() : "");
    }
}
