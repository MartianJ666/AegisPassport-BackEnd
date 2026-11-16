package io.aegis.passport.security;
import java.nio.charset.StandardCharsets;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;

/** Validate plaintext after RSA decryption, before BCrypt encoding. */
public final class PasswordPolicy {
    private PasswordPolicy() {}
    public static void validate(String password) {
        if (password == null || password.length() < 6 || password.getBytes(StandardCharsets.UTF_8).length > 72)
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "密码至少 6 个字符，且不超过 72 字节");
    }
}
