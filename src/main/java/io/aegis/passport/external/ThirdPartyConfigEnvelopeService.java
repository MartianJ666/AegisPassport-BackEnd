package io.aegis.passport.external;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.config.PassportProperties;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/** Dedicated AES-GCM envelope for upstream provider secrets in system_config. */
@Service @RequiredArgsConstructor
public class ThirdPartyConfigEnvelopeService {
    private static final int NONCE_LEN = 12;
    private final PassportProperties props;
    private final SecureRandom random = new SecureRandom();
    public boolean isAvailable() { return StringUtils.hasText(props.getThirdParty().getConfigEnvelopeKey()); }
    public String encrypt(String provider, String field, String value) {
        try {
            byte[] nonce = new byte[NONCE_LEN]; random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(provider, field));
            return "v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(nonce) + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (BusinessException e) { throw e;
        } catch (Exception e) { throw BusinessException.of(ErrorCode.INTERNAL_ERROR, "第三方登录密钥加密失败", e); }
    }
    public String decrypt(String provider, String field, String envelope) {
        try {
            String[] parts = envelope == null ? new String[0] : envelope.split("\\.", 3);
            if (parts.length != 3 || !"v1".equals(parts[0])) throw new IllegalArgumentException("invalid envelope");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.getUrlDecoder().decode(parts[1])));
            cipher.updateAAD(aad(provider, field));
            return new String(cipher.doFinal(Base64.getUrlDecoder().decode(parts[2])), StandardCharsets.UTF_8);
        } catch (BusinessException e) { throw e;
        } catch (Exception e) { throw BusinessException.of(ErrorCode.INTERNAL_ERROR, "第三方登录密钥不可用", e); }
    }
    private SecretKeySpec key() {
        try {
            String encoded = props.getThirdParty().getConfigEnvelopeKey();
            if (!StringUtils.hasText(encoded)) throw BusinessException.of(ErrorCode.BAD_REQUEST, "未配置第三方登录加密密钥");
            byte[] raw = Base64.getDecoder().decode(encoded.trim());
            if (raw.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
            return new SecretKeySpec(raw, "AES");
        } catch (BusinessException e) { throw e;
        } catch (Exception e) { throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录加密密钥格式无效"); }
    }
    private byte[] aad(String provider, String field) { return ("third-party-login:v1:" + provider + ":" + field).getBytes(StandardCharsets.UTF_8); }
}
