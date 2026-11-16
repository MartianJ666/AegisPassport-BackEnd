package io.aegis.passport.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.aegis.passport.rbac.PermissionResolver;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

class OidcTokenCustomizerConfigTest {
    private final OidcUserInfoMapper mapper = mock(OidcUserInfoMapper.class);
    private final PermissionResolver roles = mock(PermissionResolver.class);
    private final OidcTokenCustomizerConfig config = new OidcTokenCustomizerConfig(mapper, roles);

    private JwtEncodingContext context(Set<String> scopes, String type) {
        var now = Instant.now();
        return JwtEncodingContext.with(
                        JwsHeader.with(SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder().issuer("https://auth.example.com")
                                .subject("42").audience(List.of("test-client"))
                                .issuedAt(now).expiresAt(now.plusSeconds(300)))
                .principal(new UsernamePasswordAuthenticationToken("alice", "unused", List.of()))
                .authorizedScopes(scopes)
                .tokenType(new OAuth2TokenType(type))
                .build();
    }

    private void userInfo(Set<String> scopes, Set<String> codes) {
        when(mapper.map("alice", scopes)).thenReturn(new OidcUserInfo(Map.of(
                "sub", "42", "preferred_username", "alice")));
        when(roles.roleCodes(42L)).thenReturn(codes);
    }

    static Stream<Set<String>> scopes() {
        return Stream.of(Set.of(), Set.of("openid"), Set.of("openid", "email"),
                Set.of("openid", "profile"));
    }

    @ParameterizedTest
    @MethodSource("scopes")
    void groupsDoNotDependOnScopes(Set<String> scopes) {
        userInfo(scopes, Set.of("member"));
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaimAsStringList("groups"))
                .containsExactly("member");
    }

    @ParameterizedTest
    @ValueSource(strings = {"member", "admin"})
    void usesActualRoleCodes(String role) {
        var scopes = Set.of("openid");
        userInfo(scopes, Set.of(role));
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaimAsStringList("groups"))
                .containsExactly(role);
    }

    @Test
    void preservesCustomAndMultipleRolesInStableOrder() {
        var scopes = Set.of("openid");
        userInfo(scopes, Set.of("member", "custom-role", "admin"));
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaimAsStringList("groups"))
                .containsExactly("admin", "custom-role", "member");
    }

    @Test
    void emitsEmptyArrayWhenUserHasNoRoles() {
        var scopes = Set.of("openid");
        userInfo(scopes, Set.of());
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaims()).containsEntry("groups", List.of());
    }

    @Test
    void groupsCannotBeOverriddenByOtherUserInfoClaims() {
        var scopes = Set.of("openid", "profile");
        when(mapper.map("alice", scopes)).thenReturn(new OidcUserInfo(Map.of(
                "sub", "42", "groups", List.of("admin"), "role", "member")));
        when(roles.roleCodes(42L)).thenReturn(Set.of("member"));
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaims())
                .containsEntry("groups", List.of("member")).containsEntry("role", "member");
    }

    @Test
    void resolvesRolesAgainForEachIssuedIdToken() {
        var scopes = Set.of("openid");
        userInfo(scopes, Set.of("member"));
        var first = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(first);
        when(roles.roleCodes(42L)).thenReturn(Set.of("admin"));
        var next = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(next);
        assertThat(first.getClaims().build().getClaimAsStringList("groups")).containsExactly("member");
        assertThat(next.getClaims().build().getClaimAsStringList("groups")).containsExactly("admin");
    }

    @Test
    void doesNotChangeAccessTokens() {
        var ctx = context(Set.of("openid", "profile"), OAuth2TokenType.ACCESS_TOKEN.getValue());
        var before = ctx.getClaims().build().getClaims();
        config.tokenCustomizer().customize(ctx);
        assertThat(ctx.getClaims().build().getClaims()).isEqualTo(before).doesNotContainKey("groups");
        verifyNoInteractions(mapper, roles);
    }

    @Test
    void signedIdTokenContainsArrayWithoutProfileScope() throws Exception {
        var scopes = Set.of("openid");
        userInfo(scopes, Set.of("member"));
        var ctx = context(scopes, OidcParameterNames.ID_TOKEN);
        config.tokenCustomizer().customize(ctx);
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keyPair = generator.generateKeyPair();
        var key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate()).keyID("test-groups").build();
        var encoder = new NimbusJwtEncoder((selector, securityContext) -> selector.select(new JWKSet(key)));
        var jwt = encoder.encode(JwtEncoderParameters.from(
                ctx.getJwsHeader().build(), ctx.getClaims().build()));
        var signed = SignedJWT.parse(jwt.getTokenValue());
        assertThat(signed.verify(new RSASSAVerifier(key.toRSAPublicKey()))).isTrue();
        assertThat(signed.getJWTClaimsSet().getStringListClaim("groups")).containsExactly("member");
        assertThat(signed.getJWTClaimsSet().getSubject()).isEqualTo("42");
        assertThat(signed.getJWTClaimsSet().getClaim("role")).isNull();
    }
}
