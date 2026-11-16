package io.aegis.passport.oauth;

import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.client.entity.OAuthClient;
import java.util.Arrays;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;

/**
 * Adapts our {@link OAuthClient} JPA entity to Spring Authorization Server's
 * {@link RegisteredClient} interface. Reads are on the hot path (every OAuth2
 * request), but since our entity is already cached the DB isn't hit repeatedly.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuthClientRepository clientRepository;

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        // Client persistence is managed via OAuthClientService + REST API,
        // not through this SAS callback.
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findById(String id) {
        try {
            Long dbId = Long.parseLong(id);
            return clientRepository.findById(dbId)
                    .map(this::toRegisteredClient).orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient).orElse(null);
    }

    private RegisteredClient toRegisteredClient(OAuthClient c) {
        if (!c.isEnabled()) {
            return null;
        }
        var builder = RegisteredClient.withId(c.getId().toString())
                .clientId(c.getClientId())
                .clientSecret(c.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        // Only truly public clients (secret is a {noop} placeholder) may use the
        // NONE (public) client authentication method. Confidential clients with a
        // real secret must NOT be downgradeable to public, otherwise a stolen
        // authorization code can be exchanged without the client secret.
        boolean publicClient = c.getClientSecret() != null
                && c.getClientSecret().startsWith("{noop}");
        if (publicClient) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }

        Arrays.stream(c.getGrantTypes().split(","))
                .map(String::trim).map(AuthorizationGrantType::new)
                .forEach(builder::authorizationGrantType);
        Arrays.stream(c.getScopes().split(","))
                .map(String::trim).forEach(builder::scope);
        Arrays.stream(c.getRedirectUris().split(","))
                .map(String::trim).forEach(builder::redirectUri);

        builder.clientSettings(ClientSettings.builder()
                .requireProofKey(c.isRequirePkce())
                .requireAuthorizationConsent(c.isRequireConsent())
                .build());
        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(c.getAccessTokenTtl()))
                .refreshTokenTimeToLive(Duration.ofSeconds(c.getRefreshTokenTtl()))
                .authorizationCodeTimeToLive(Duration.ofSeconds(c.getAuthorizationCodeTtl()))
                // Rotate refresh tokens so a leaked token can't be reused forever.
                .reuseRefreshTokens(false)
                .build());

        return builder.build();
    }
}
