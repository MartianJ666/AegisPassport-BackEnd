package io.aegis.passport.session;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user/sessions")
@RequiredArgsConstructor
class SessionVerificationController {
    private final UserRepository users;
    private final SessionVerificationService verification;
    private final SessionService sessions;
    private final RsaTransportService rsa;
    private final PasswordEncoder passwords;
    private final CaptchaService captcha;

    @PostMapping("/captcha")
    public ResponseEntity<ApiResult<CaptchaService.Challenge>> captcha() {
        return ResponseEntity.ok(ApiResult.ok(captcha.issue(String.valueOf(SecurityUtils.currentUserId()), "SESSION_VERIFICATION_CODE")));
    }

    @PostMapping("/verification-code")
    public ResponseEntity<ApiResult<Void>> send(@RequestBody CaptchaRequest req) {
        String userId=String.valueOf(SecurityUtils.currentUserId());
        if(!captcha.verifyAndConsume(req.getCaptchaId(), req.getCaptchaAnswer(), userId, "SESSION_VERIFICATION_CODE")) throw BusinessException.of(ErrorCode.BAD_REQUEST, "人机验证答案不正确或已过期");
        users.findById(SecurityUtils.currentUserId()).ifPresent(verification::send);
        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/revoke-verified")
    public ResponseEntity<ApiResult<java.util.Map<String,Object>>> revokeVerified(@Valid @RequestBody VerifiedRevokeRequest req, jakarta.servlet.http.HttpServletRequest request) {
        var user=users.findById(SecurityUtils.currentUserId()).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        if(!passwords.matches(rsa.decryptStrict(req.getPasswordEncrypted()), user.getPassword())) throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS,"密码错误");
        if(!verification.verify(user, req.getCode())) throw BusinessException.of(ErrorCode.VERIFICATION_CODE_INVALID);
        int count=sessions.revokeOwned(user.getId(), req.getSessionIds(), user.getUsername(), "USER_REVOKE_VERIFIED");
        String current = SessionService.sessionId(request);
        boolean currentRevoked = current != null && req.getSessionIds().contains(current);
        if (currentRevoked && request.getSession(false) != null) request.getSession(false).invalidate();
        return ResponseEntity.ok(ApiResult.ok(java.util.Map.of("revokedCount",count,"currentRevoked",currentRevoked)));
    }
    @Data static class CaptchaRequest { private String captchaId; private String captchaAnswer; }
    @Data static class VerifiedRevokeRequest { @NotBlank private String passwordEncrypted; @NotBlank private String code; @jakarta.validation.constraints.NotEmpty @jakarta.validation.constraints.Size(max=100) private List<@NotBlank String> sessionIds=List.of(); }
}
