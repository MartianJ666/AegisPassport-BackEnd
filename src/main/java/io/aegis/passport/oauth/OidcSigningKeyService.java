package io.aegis.passport.oauth;

import io.aegis.passport.oauth.entity.SigningKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages the RSA key pair that signs OIDC ID tokens. The active key is
 * persisted in {@code signing_keys} so tokens remain verifiable across
 * restarts — the original code generated a fresh key every boot, invalidating
 * all live ID tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OidcSigningKeyService {

    private final SigningKeyRepository signingKeyRepository;

    /** Returns the current active {@link KeyPair}, creating and persisting one if absent. */
    @Transactional
    public KeyPair getOrCreateKeyPair() {
        List<SigningKey> active = signingKeyRepository.findByActiveTrueOrderByCreatedAtDesc();
        if (!active.isEmpty()) {
            return decode(active.get(0));
        }
        return createAndStore();
    }

    @Transactional(readOnly = true)
    public String getCurrentKeyId() {
        return signingKeyRepository.findByActiveTrueOrderByCreatedAtDesc()
                .stream().findFirst()
                .map(SigningKey::getKeyId)
                .orElseThrow(() -> new IllegalStateException("签名密钥不存在"));
    }

    private KeyPair createAndStore() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();
            String keyId = UUID.randomUUID().toString().replace("-", "");
            signingKeyRepository.save(SigningKey.builder()
                    .keyId(keyId)
                    .publicKey(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()))
                    .privateKey(Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()))
                    .active(true)
                    .build());
            log.info("[OIDC] 已生成并持久化新的签名密钥 keyId={}", keyId);
            return kp;
        } catch (Exception e) {
            throw new IllegalStateException("OIDC 签名密钥生成失败", e);
        }
    }

    private KeyPair decode(SigningKey sk) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(sk.getPublicKey())));
            RSAPrivateKey priv = (RSAPrivateKey) kf.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(sk.getPrivateKey())));
            return new KeyPair(pub, priv);
        } catch (Exception e) {
            throw new IllegalStateException("签名密钥解码失败", e);
        }
    }
}
