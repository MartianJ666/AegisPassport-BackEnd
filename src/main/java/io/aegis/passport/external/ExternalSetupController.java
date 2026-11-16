package io.aegis.passport.external;

import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.external.entity.ExternalIdentity;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/external/setup")
@RequiredArgsConstructor
public class ExternalSetupController {
    private final UserRepository users;
    private final ExternalIdentityRepository identities;
    private final ExternalLoginService loginService;
    private final RsaTransportService rsa;
    private final PasswordEncoder passwordEncoder;

    /** Self-service sign-up switch: closes external-account onboarding. */
    @Value("${passport.registration.self-service-enabled:false}")
    private boolean selfServiceRegistrationEnabled;

    @PostMapping
    @Audit(module = "external-auth", action = "SETUP_COMPLETE", description = "完成第三方新账号设置")
    @Transactional
    public ResponseEntity<ApiResult<Void>> setup(@Valid @RequestBody SetupRequest req,
            HttpServletRequest request, HttpServletResponse response) {
        if (!selfServiceRegistrationEnabled) {
            throw BusinessException.of(ErrorCode.REGISTRATION_DISABLED);
        }
        User user = requireNeedsSetup();
        String email = normalize(req.getEmail());
        User emailOwner = users.findByEmail(email).orElse(null);
        if (emailOwner != null && !emailOwner.getId().equals(user.getId())) {
            throw BusinessException.of(ErrorCode.EMAIL_TAKEN_MERGE_AVAILABLE);
        }
        String username = req.getUsername().trim();
        User nameOwner = users.findByUsername(username).orElse(null);
        if (nameOwner != null && !nameOwner.getId().equals(user.getId())) {
            throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS, "用户名已被占用");
        }
        String plain = rsa.decrypt(req.getPasswordEncrypted());
        io.aegis.passport.security.PasswordPolicy.validate(plain);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(plain));
        user.setNeedsSetup(false);
        users.save(user);
        // The username changed, so the existing JWT (subject=old username) is stale.
        loginService.reissue(user, request, response);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/merge")
    @Audit(module = "external-auth", action = "SETUP_MERGE", description = "合并第三方新账号到已有账号")
    @Transactional
    public ResponseEntity<ApiResult<MergeResponse>> merge(@Valid @RequestBody MergeRequest req,
            HttpServletRequest request, HttpServletResponse response) {
        if (!selfServiceRegistrationEnabled) {
            throw BusinessException.of(ErrorCode.REGISTRATION_DISABLED);
        }
        User temp = requireNeedsSetup();
        User existing = users.findByUsername(req.getUsername().trim())
                .orElseThrow(() -> BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "目标账号用户名或密码错误"));
        String plain = rsa.decrypt(req.getPasswordEncrypted());
        if (!passwordEncoder.matches(plain, existing.getPassword())) {
            throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "目标账号用户名或密码错误");
        }
        // Move every identity owned by the temporary user to the existing account.
        // The unique key will return the very identity being moved, so only treat a
        // DIFFERENT identity row (a genuine ownership conflict) as already-bound.
        ExternalIdentity moved = null;
        for (ExternalIdentity identity : identities.findByUserIdOrderByCreatedAtDesc(temp.getId())) {
            ExternalIdentity same = identities.findByProviderAndIssuerAndProviderSubject(
                    identity.getProvider(), identity.getIssuer(), identity.getProviderSubject()).orElse(null);
            if (same != null && !same.getId().equals(identity.getId())) {
                throw BusinessException.of(ErrorCode.EXTERNAL_IDENTITY_ALREADY_BOUND);
            }
            identity.setUser(existing);
            identity.setLastAuthenticatedAt(Instant.now());
            moved = identities.save(identity);
        }
        // Force a password reset on the merged account as part of the merge.
        String newPlain = rsa.decrypt(req.getNewPasswordEncrypted());
        io.aegis.passport.security.PasswordPolicy.validate(newPlain);
        existing.setPassword(passwordEncoder.encode(newPlain));
        existing.setNeedsSetup(false);
        users.save(existing);
        users.delete(temp);
        if (moved != null) {
            loginService.reissue(existing, request, response);
        }
        return ResponseEntity.ok(ApiResult.ok(new MergeResponse(existing.getUsername())));
    }

    private User requireNeedsSetup() {
        Long userId = SecurityUtils.currentUserId();
        User user = users.findById(userId).orElseThrow(() -> BusinessException.of(ErrorCode.UNAUTHORIZED));
        if (!user.isNeedsSetup()) throw BusinessException.of(ErrorCode.BAD_REQUEST, "账号已设置完成");
        return user;
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    @Data
    public static class SetupRequest {
        @NotBlank @Size(min = 3, max = 50) private String username;
        @NotBlank @Email private String email;
        @NotBlank private String passwordEncrypted;
    }

    @Data
    public static class MergeRequest {
        @NotBlank private String username;
        @NotBlank private String passwordEncrypted;
        @NotBlank private String newPasswordEncrypted;
    }

    @Data
    public static class MergeResponse {
        private final String username;
        public MergeResponse(String username) { this.username = username; }
    }
}
