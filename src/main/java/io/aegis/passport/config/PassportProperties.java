package io.aegis.passport.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Strongly-typed binding for all {@code passport.*} settings. Injected wherever
 * configuration is needed instead of scattering {@code @Value} lookups.
 */
@Data
@ConfigurationProperties(prefix = "passport")
public class PassportProperties {

    private String issuer = "http://localhost:8421";
    private String frontendUrl = "http://localhost:8420";
    private String corsAllowedOrigins = "http://localhost:8420";

    private Jwt jwt = new Jwt();
    private Security security = new Security();
    private Upload upload = new Upload();
    private BootstrapAdmin bootstrapAdmin = new BootstrapAdmin();
    private Cache cache = new Cache();
    private Consent consent = new Consent();
    private ThirdParty thirdParty = new ThirdParty();

    @Data
    public static class Jwt {
        private String secret = "";
        private long expirationMs = 86_400_000L;
    }

    @Data
    public static class Security {
        private Login login = new Login();

        @Data
        public static class Login {
            private int maxAttempts = 5;
            private int lockSeconds = 300;
        }
    }

    @Data
    public static class Upload {
        private String dir = "uploads";
        private String urlPrefix = "/uploads";
    }

    @Data
    public static class BootstrapAdmin {
        private String username = "admin";
        private String password = "";
    }

    @Data
    public static class Cache {
        /** {@code redis} or {@code memory}. */
        private String provider = "memory";
    }



    @Data
    public static class ThirdParty {
        /** Base64-encoded 32-byte AES key dedicated to third-party provider secrets. */
        private String configEnvelopeKey = "";
    }

    @Data
    public static class Consent {
        /** Public base URL of the consent page (e.g. https://sso.example.com).
         *  Blank falls back to {@link PassportProperties#getFrontendUrl()}. */
        private String baseUrl = "";
    }

}
