package io.aegis.passport.oauth;

import io.aegis.passport.rbac.PermissionResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Adds groups to every issued ID token, independently of the authorized scopes.
 * Other user-info claims retain their existing scope rules.
 */
@Configuration
@RequiredArgsConstructor
public class OidcTokenCustomizerConfig {

    private final OidcUserInfoMapper userInfoMapper;
    private final PermissionResolver permissionResolver;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return ctx -> {
            if (OidcParameterNames.ID_TOKEN.equals(ctx.getTokenType().getValue())) {
                var scopes = ctx.getAuthorizedScopes();
                var username = ctx.getPrincipal().getName();
                var userInfo = userInfoMapper.map(username, scopes);
                var groups = permissionResolver.roleCodes(Long.valueOf(userInfo.getSubject()))
                        .stream().sorted().toList();
                ctx.getClaims().claims(claims -> {
                    claims.putAll(userInfo.getClaims());
                    claims.put("groups", groups);
                });
            }
        };
    }
}
