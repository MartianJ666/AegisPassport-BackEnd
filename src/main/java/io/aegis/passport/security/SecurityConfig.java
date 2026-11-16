package io.aegis.passport.security;
import com.nimbusds.jose.jwk.JWKSet; import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet; import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.client.OAuthClientRepository;
import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.external.NeedsSetupFilter;
import io.aegis.passport.oauth.AuditedOAuth2AuthorizationService;
import io.aegis.passport.oauth.OidcSigningKeyService; import io.aegis.passport.oauth.OidcUserInfoMapper;
import java.net.URLEncoder; import java.nio.charset.StandardCharsets;
import java.security.KeyPair; import java.security.interfaces.RSAPrivateKey; import java.security.interfaces.RSAPublicKey;
import java.util.Arrays; import java.util.List;
import lombok.RequiredArgsConstructor; import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean; import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration; import org.springframework.web.cors.CorsConfigurationSource; import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
@Slf4j @Configuration @EnableWebSecurity @EnableMethodSecurity @RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtFilter;
    private final ConsentCsrfOriginFilter consentCsrfOriginFilter;
    private final AccountConfirmFilter accountConfirmFilter;
    private final SecurityViolationFilter violationFilter;
    private final NeedsSetupFilter needsSetupFilter;
    private final OidcSigningKeyService signingKeyService;
    private final OidcUserInfoMapper oidcUserInfoMapper;
    private final PassportProperties props;
    @Bean @Order(1)
    public SecurityFilterChain authServerChain(HttpSecurity http) throws Exception {
        http.oauth2AuthorizationServer(server -> server
                        .oidc(oidc -> oidc.userInfoEndpoint(ep -> ep.userInfoMapper(ctx -> oidcUserInfoMapper.map(ctx.getAuthentication().getName(), ctx.getAccessToken().getScopes()))))
                        .authorizationEndpoint(ep -> ep.consentPage("/oauth2/consent-redirect")));
        var endpointsMatcher = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .cors(Customizer.withDefaults()).csrf(csrf -> csrf.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .addFilterBefore(consentCsrfOriginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(accountConfirmFilter, SecurityContextHolderFilter.class)
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor((req, res, e) -> res.sendRedirect(props.getFrontendUrl() + "/auth/login?redirect=" + URLEncoder.encode(req.getRequestURL() + (req.getQueryString() != null ? "?" + req.getQueryString() : ""), StandardCharsets.UTF_8)), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
        return http.build();
    }
    @Bean @Order(2)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults()).csrf(csrf -> csrf.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth-continue.js").permitAll()
                        .requestMatchers("/api/auth/**", "/api/oauth/temp-login", "/api/consent/info", "/api/account-confirm/info", "/api/rsa/public-key", "/api/public/**", "/api/config/login", "/api/external-identities/providers", "/api/external-identities/*/start", "/api/external-identities/*/callback", "/uploads/**", "/oauth2/consent", "/oauth2/consent-redirect", "/oauth2/jwks", "/logout", "/connect/logout", "/.well-known/**", "/h2-console/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(fl -> fl.disable()).httpBasic(hb -> hb.disable())
                .logout(lo -> lo.logoutUrl("/logout").logoutSuccessUrl(props.getFrontendUrl() + "/auth/login?logout").invalidateHttpSession(true).deleteCookies("__Host-passport-session", "__Host-passport-token").permitAll())
                // An invalid/expired token is NOT a permission denial. Return 401
                // (not the default 403) so the SPA's 401 interceptor clears the stale
                // session and redirects to login instead of showing "没有权限".
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(401);
                    res.setContentType("application/json;charset=UTF-8");
                    res.getWriter().write("{\"code\":401,\"errorCode\":\"UNAUTHORIZED\",\"message\":\"未认证或登录已失效\"}");
                }))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(violationFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(needsSetupFilter, JwtAuthenticationFilter.class)
                .headers(h -> h.frameOptions(fo -> fo.sameOrigin())
                        .contentTypeOptions(Customizer.withDefaults()));
        return http.build();
    }
    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
    @Bean
    public OAuth2AuthorizationService oauth2AuthorizationService(
            OAuthClientRepository clientRepo, AuditLogService auditLogService,
            io.aegis.passport.user.UserRepository users) {
        // Wraps the default in-memory store so a code issuance (user authorizing a
        // login to an app) is recorded in the audit log.
        return new AuditedOAuth2AuthorizationService(
                new InMemoryOAuth2AuthorizationService(), auditLogService, clientRepo, users);
    }
    @Bean
    public AuthenticationManager authenticationManager(PassportUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        var provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setHideUserNotFoundExceptions(false); return new ProviderManager(provider);
    }
    @Bean public JWKSource<SecurityContext> jwkSource() {
        KeyPair kp = signingKeyService.getOrCreateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) kp.getPublic()).privateKey((RSAPrivateKey) kp.getPrivate()).keyID(signingKeyService.getCurrentKeyId()).build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }
    @Bean public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) { return NimbusJwtDecoder.withJwkSource(jwkSource).build(); }
    @Bean public AuthorizationServerSettings authorizationServerSettings() { return AuthorizationServerSettings.builder().issuer(props.getIssuer()).build(); }
    @Bean public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of(props.getCorsAllowedOrigins().split(",")));
        cfg.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*")); cfg.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg); return source;
    }
}
