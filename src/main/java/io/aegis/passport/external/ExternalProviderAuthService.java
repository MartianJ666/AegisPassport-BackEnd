package io.aegis.passport.external;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.external.entity.ExternalAuthTransaction;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExternalProviderAuthService {

    private final ThirdPartyLoginConfigService configService;
    private final ExternalAuthTransactionService transactionService;
    private final ExternalLoginService loginService;
    private final ExternalAccountService accountService;
    private final JsonMapper objectMapper;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();

    public boolean isPubliclyAvailable(String provider) {
        return isSupported(provider) && configService.isEnabledAndReady(provider);
    }

    public StartResult start(String provider) {
        return startInternal(provider, null);
    }

    public StartResult startLink(String provider, User user) {
        if (user == null) throw BusinessException.of(ErrorCode.UNAUTHORIZED);
        return startInternal(provider, user);
    }

    private StartResult startInternal(String provider, User user) {
        if (!isPubliclyAvailable(provider)) {
            throw BusinessException.of(ErrorCode.NOT_FOUND);
        }
        boolean oidc = isOidc(provider);
        String verifier = oidc ? transactionService.random(48) : null;
        String nonce = oidc ? transactionService.random(24) : null;
        ExternalAuthTransactionService.Start tx = transactionService.create(provider, verifier, nonce, user,
                user != null ? "LINK" : "LOGIN");
        ThirdPartyLoginConfigService.ProviderRuntime cfg = configService.runtime(provider);
        OidcEndpoints endpoints = discovery(cfg.issuer());
        String url = oidcAuthorizationUrl(cfg, tx, endpoints.authorization());
        return new StartResult(url, tx.browser(), tx.id());
    }

    public CompleteResult complete(String provider, String txId, String state, String code, String callbackType,
                                   String browserCookie, HttpServletRequest request, HttpServletResponse response) {
        if (!isPubliclyAvailable(provider) || !StringUtils.hasText(txId) || !StringUtils.hasText(state)
                || !StringUtils.hasText(browserCookie) || !StringUtils.hasText(code)) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录未完成");
        }
        ExternalAuthTransaction tx = transactionService.consume(provider, txId, state, browserCookie);
        ThirdPartyLoginConfigService.ProviderRuntime cfg = configService.runtime(provider);
        // Transactions for retired or unknown flows must never become login/link requests.
        if (!"LOGIN".equals(tx.getIntent()) && !"LINK".equals(tx.getIntent())) {
            throw invalidState();
        }
        OidcEndpoints endpoints = discovery(cfg.issuer());
        ExternalProviderIdentity identity = oidcIdentity(cfg, tx, code, endpoints.issuer(), endpoints.token());
        if (tx.getUser() != null) {
            accountService.bindToUser(tx.getUser().getId(), identity);
            return new CompleteResult(true, false);
        }
        boolean needsSetup = loginService.authenticate(identity, request, response);
        return new CompleteResult(false, needsSetup);
    }

    public ParsedState parseOidcState(String state) {
        if (!StringUtils.hasText(state)) throw invalidState();
        String[] values = state.split("\\.", 2);
        if (values.length != 2 || values[0].isBlank() || values[1].isBlank()) throw invalidState();
        return new ParsedState(values[0], values[1]);
    }





    private String oidcAuthorizationUrl(ThirdPartyLoginConfigService.ProviderRuntime cfg,
                                        ExternalAuthTransactionService.Start tx, String authorizationEndpoint) {
        String state = tx.id() + "." + tx.state();
        return authorizationEndpoint + "?response_type=code&client_id=" + encode(cfg.publicId())
                + "&redirect_uri=" + encode(cfg.callbackUrl()) + "&scope=" + encode("openid profile email")
                + "&state=" + encode(state) + "&nonce=" + encode(tx.nonce())
                + "&code_challenge=" + encode(base64Url(sha256(tx.pkceVerifier())))
                + "&code_challenge_method=S256";
    }

    private ExternalProviderIdentity oidcIdentity(ThirdPartyLoginConfigService.ProviderRuntime cfg,
                                                  ExternalAuthTransaction tx, String code,
                                                  String issuer, String tokenEndpoint) {
        JsonNode payload = exchangeToken(cfg, tokenEndpoint, code, tx.getPkceVerifier());
        Jwt jwt = validateJwt(cfg, tx, payload.path("id_token").asText(), issuer);
        String email = Boolean.TRUE.equals(jwt.getClaim("email_verified")) ? jwt.getClaimAsString("email") : null;
        return new ExternalProviderIdentity(cfg.provider(), issuer, jwt.getSubject(),
                jwt.getClaimAsString("name"), jwt.getClaimAsString("picture"), email);
    }

    private JsonNode exchangeToken(ThirdPartyLoginConfigService.ProviderRuntime cfg, String tokenEndpoint,
                                   String code, String verifier) {
        String form = "grant_type=authorization_code&code=" + encode(code)
                + "&redirect_uri=" + encode(cfg.callbackUrl())
                + "&client_id=" + encode(cfg.publicId())
                + "&code_verifier=" + encode(verifier);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                .timeout(Duration.ofSeconds(12))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        if (StringUtils.hasText(cfg.secret())) {
            builder.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    (cfg.publicId() + ":" + cfg.secret()).getBytes(StandardCharsets.UTF_8)));
        }
        return sendJson(builder.build(), "OIDC 授权码交换失败");
    }

    private Jwt validateJwt(ThirdPartyLoginConfigService.ProviderRuntime cfg, ExternalAuthTransaction tx,
                            String idToken, String issuer) {
        if (!StringUtils.hasText(idToken)) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方身份令牌缺失");
        try {
            NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer) instanceof NimbusJwtDecoder value ? value : null;
            if (decoder == null) throw new IllegalStateException("decoder unavailable");
            decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
            Jwt jwt = decoder.decode(idToken);
            boolean audience = jwt.getAudience().contains(cfg.publicId());
            boolean authorizedParty = jwt.getAudience().size() <= 1 || cfg.publicId().equals(jwt.getClaimAsString("azp"));
            if (!audience || !authorizedParty || !tx.getNonce().equals(jwt.getClaimAsString("nonce"))
                    || !StringUtils.hasText(jwt.getSubject())) {
                throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方身份令牌无效");
            }
            return jwt;
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.warn("OIDC identity token validation failed: {}", e.getClass().getSimpleName());
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方身份验证失败");
        }
    }

    private OidcEndpoints discovery(String issuer) {
        if (!issuer.startsWith("https://")) throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录 issuer 无效");
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(issuer.replaceAll("/+$", "")
                    + "/.well-known/openid-configuration")).timeout(Duration.ofSeconds(8)).GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode doc = objectMapper.readTree(response.body());
            String discoveredIssuer = doc.path("issuer").asText();
            String authorization = doc.path("authorization_endpoint").asText();
            String token = doc.path("token_endpoint").asText();
            if (response.statusCode() != 200 || !issuer.equals(discoveredIssuer)
                    || !authorization.startsWith("https://") || !token.startsWith("https://")) {
                throw new IllegalStateException("invalid discovery");
            }
            return new OidcEndpoints(discoveredIssuer, authorization, token);
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.warn("OIDC discovery failed for {}: {}", issuer, e.getClass().getSimpleName());
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录配置不可用");
        }
    }

    private JsonNode getJson(String url, String message) {
        return sendJson(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(12)).GET().build(), message);
    }

    private JsonNode sendJson(HttpRequest request, String message) {
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IllegalStateException("unexpected status");
            return objectMapper.readTree(response.body());
        } catch (Exception e) {
            log.warn("External provider request failed: {}", e.getClass().getSimpleName());
            throw BusinessException.of(ErrorCode.BAD_REQUEST, message);
        }
    }





    private static boolean isSupported(String provider) {
        return "oidc".equals(provider);
    }

    private static boolean isOidc(String provider) {
        return "oidc".equals(provider);
    }



    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static BusinessException invalidState() {
        return BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录状态无效或已过期");
    }

    public record StartResult(String url, String browserCookie, String transactionId) {}
    public record ParsedState(String txId, String state) {}
    public record CompleteResult(boolean linked, boolean needsSetup) {}
    private record OidcEndpoints(String issuer, String authorization, String token) {}
}
