package io.aegis.passport.external;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.systemconfig.SystemConfigService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/** Runtime provider configuration backed by system_config; secrets are write-only AES-GCM envelopes. */
@Service
@RequiredArgsConstructor
public class ThirdPartyLoginConfigService {
    private static final String PREFIX = "third-party-login.";
    private final SystemConfigService configs;
    private final ThirdPartyConfigEnvelopeService envelope;
    private final PassportProperties props;

    public AdminView adminView() {
        return new AdminView(provider("oidc", "OpenID Connect", true));
    }

    @Transactional
    public AdminView save(SaveRequest request) {
        saveOidc("oidc", request.getOidc());
        return adminView();
    }

    public ProviderRuntime runtime(String provider) {
        ProviderView v = provider(provider, displayName(provider), true);
        if (!v.isReady()) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录配置不完整");
        String secret = decrypt(provider, secretField(provider));
        if (!StringUtils.hasText(secret)) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录密钥不可用");
        String issuer = issuerOf(provider);
        if (!StringUtils.hasText(issuer)) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录 issuer 未配置");
        return new ProviderRuntime(provider, v.isEnabled(), v.getPublicId(), secret, v.getCallbackUrl(), issuer);
    }

    public boolean isEnabledAndReady(String provider) {
        try {
            ProviderView view = provider(provider, displayName(provider), true);
            return view.isEnabled() && view.isReady();
        } catch (Exception ignored) {
            return false;
        }
    }



    private void saveOidc(String provider, ProviderInput input) {
        if (input == null) return;
        String issuer = nonBlank(input.getIssuer());
        if (issuer != null) {
            if (!issuer.startsWith("https://")) throw BusinessException.of(ErrorCode.BAD_REQUEST, "Issuer 必须是 HTTPS 地址");
            set(key(provider, "issuer"), issuer);
        }
        String publicId = nonBlank(input.getClientId());
        if (publicId != null) set(key(provider, "client-id"), publicId);
        replaceSecret(provider, "client-secret", input.getClientSecret());
        setEnabled(provider, input.getEnabled(), "client-id", "client-secret", "issuer");
    }

    private void replaceSecret(String provider, String field, String value) {
        String secret = nonBlank(value);
        if (secret != null) {
            if (!envelope.isAvailable()) throw BusinessException.of(ErrorCode.BAD_REQUEST, "服务器未配置第三方登录加密密钥");
            if (secret.length() > 2048) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录密钥过长");
            set(key(provider, field + ".envelope"), envelope.encrypt(provider, field, secret));
        }
    }

    private void setEnabled(String provider, Boolean enabled, String idField, String secretField, String issuerField) {
        if (enabled == null) return;
        boolean ok = StringUtils.hasText(get(key(provider, idField)))
                && StringUtils.hasText(get(key(provider, secretField + ".envelope")))
                && (issuerField == null || StringUtils.hasText(get(key(provider, issuerField))));
        if (enabled && !ok) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "请先完整填写配置后再启用");
        }
        set(key(provider, "enabled"), Boolean.toString(enabled));
    }

    private ProviderView provider(String provider, String name, boolean editable) {
        String idField = isOidc(provider) ? "client-id" : "app-id";
        String secretField = secretField(provider);
        String publicId = get(key(provider, idField));
        boolean secretConfigured = StringUtils.hasText(get(key(provider, secretField + ".envelope")));
        boolean enabled = Boolean.parseBoolean(get(key(provider, "enabled")));
        String issuer = issuerOf(provider);
        boolean ready = StringUtils.hasText(publicId) && secretConfigured && envelope.isAvailable()
                && (!isOidc(provider) || StringUtils.hasText(issuer));
        String callback = callback(provider);
        String reason = ready ? null : (!envelope.isAvailable() ? "服务器尚未配置专用加密密钥" : "尚未完整填写配置");
        String scopes = isOidc(provider) ? "openid profile email" : "openid profile email";
        return new ProviderView(provider, name, editable, enabled, ready, publicId, secretConfigured,
                callback, reason, scopes, issuer);
    }

    private String issuerOf(String provider) { return get(key(provider, "issuer")); }

    private boolean isOidc(String provider) {
        return "oidc".equals(provider);
    }

    private String callback(String provider) {
        String origin = props.getFrontendUrl().replaceAll("/+$", "");
        return origin + "/api/external-identities/" + provider + "/callback";
    }

    private String secretField(String provider) { return isOidc(provider) ? "client-secret" : "app-key"; }
    private String displayName(String provider) { return switch (provider) {
        case "oidc" -> "OpenID Connect";
        default -> throw BusinessException.of(ErrorCode.NOT_FOUND);
    }; }
    private String decrypt(String provider, String field) { String raw = get(key(provider, field + ".envelope")); return StringUtils.hasText(raw) ? envelope.decrypt(provider, field, raw) : null; }
    private String key(String provider, String field) { return PREFIX + provider + "." + field; }
    private String get(String key) { return configs.get(key, ""); }
    private void set(String key, String value) { configs.set(key, value, "third-party-login"); }
    private static String nonBlank(String value) { return StringUtils.hasText(value) ? value.trim() : null; }

    @Data public static class ProviderInput {
        private Boolean enabled;
        private String clientId; private String clientSecret; private String issuer;
    }
    @Data public static class SaveRequest {
        private ProviderInput oidc;
    }
    @Data public static class ProviderView {
        private final String id, name; private final boolean editable, enabled, ready; private final String publicId;
        private final boolean secretConfigured; private final String callbackUrl, disabledReason, scopes, issuer;
    }
    @Data public static class AdminView {
        private final ProviderView oidc;
    }
    public record ProviderRuntime(String provider, boolean enabled, String publicId, String secret,
                                  String callbackUrl, String issuer) {}
}
