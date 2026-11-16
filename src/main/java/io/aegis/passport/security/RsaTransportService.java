package io.aegis.passport.security;

import jakarta.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Temporary per-startup RSA key pair for password transport encryption.
 * The frontend fetches the public key, RSA-encrypts the password, and the
 * server decrypts with the private key before hashing with BCrypt. Provides
 * defence-in-depth even over plain HTTP (e.g. local dev); over HTTPS the
 * transport itself is already encrypted but this layer costs nothing.
 *
 * <p>A new key is generated on each startup — this is intentional. Stale
 * ciphertexts from a previous session are silently rejected by {@link #decrypt}
 * (falls back to treating the value as plaintext so the UI can send plaintext
 * when RSA initialisation hasn't been done).
 */
@Slf4j
@Service
public class RsaTransportService {

    private static final int KEY_SIZE = 2048;
    @Getter private KeyPair keyPair;

    @PostConstruct
    public void init() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(KEY_SIZE);
            keyPair = gen.generateKeyPair();
            log.info("[RSA] 密码传输密钥已生成（{}位）", KEY_SIZE);
        } catch (Exception e) {
            throw new IllegalStateException("RSA 密钥生成失败", e);
        }
    }

    /** Base64-encoded DER X.509 public key. */
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /**
     * Decrypts a Base64-encoded RSA-PKCS1-v1.5 ciphertext. Returns the input
     * unchanged if decryption fails so callers can accept either encrypted or
     * plaintext passwords (useful during local dev or when JS encryption is
     * disabled).
     */
    public String decrypt(String cipherOrPlain) {
        if (cipherOrPlain == null) {
            return null;
        }
        try {
            return decryptStrict(cipherOrPlain);
        } catch (IllegalArgumentException e) {
            log.debug("[RSA] 解密失败，当作明文处理");
            return cipherOrPlain;
        }
    }

    /** Decrypts RSA ciphertext and rejects plaintext fallback for private service calls. */
    public String decryptStrict(String ciphertext) {
        if (ciphertext == null || ciphertext.isBlank()) {
            throw new IllegalArgumentException("加密密码不能为空");
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(ciphertext);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            return new String(cipher.doFinal(bytes));
        } catch (Exception e) {
            throw new IllegalArgumentException("密码加密数据无效");
        }
    }
}
