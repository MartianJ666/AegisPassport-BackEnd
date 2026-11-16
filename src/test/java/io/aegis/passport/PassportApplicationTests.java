package io.aegis.passport;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@ActiveProfiles("local")
@TestPropertySource(properties = {
        "passport.jwt.secret=aegis-test-secret-change-me-please-32bytes-minimum",
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class PassportApplicationTests {
    @org.springframework.beans.factory.annotation.Autowired
    org.springframework.web.context.WebApplicationContext web;
    @org.springframework.beans.factory.annotation.Autowired
    io.aegis.passport.client.OAuthClientRepository clients;

    @Test
    void unauthenticatedAuthorizationRedirectsToLogin() throws Exception {
        clients.save(io.aegis.passport.client.entity.OAuthClient.builder()
                .clientId("example-client").clientName("Example client").clientSecret("{noop}test")
                .redirectUris("https://example.com/callback").build());
        var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web)
                .apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity()).build();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/authorize")
                .queryParam("client_id","example-client").queryParam("response_type","code")
                .queryParam("redirect_uri","https://example.com/callback").queryParam("scope","openid")
                .queryParam("code_challenge","012345678901234567890123456789012345678901234")
                .queryParam("code_challenge_method","S256").accept("text/html"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isFound())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Location",org.hamcrest.Matchers.containsString("/auth/login?redirect=")));
    }

    @Test
    void contextLoads() {
        // Verifies the Spring context starts without errors.
    }

    @Test
    void retiredFeatureRoutesAreAbsentAndAccountRoutesRemain() {
        var mappings = web.getBean("requestMappingHandlerMapping",
                org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.class);
        var paths = mappings.getHandlerMethods().keySet().stream()
                .flatMap(info -> info.getPatternValues().stream()).collect(java.util.stream.Collectors.toSet());
        org.junit.jupiter.api.Assertions.assertTrue(paths.contains("/api/files/avatar"));
        org.junit.jupiter.api.Assertions.assertTrue(paths.contains("/api/external-identities/{provider}/bind"));
        org.junit.jupiter.api.Assertions.assertTrue(paths.contains("/api/config/admin/security/session-policy"));
        org.junit.jupiter.api.Assertions.assertFalse(paths.stream().anyMatch(path -> path.startsWith("/api/reauth") || path.startsWith("/api/auth/reauth") || path.startsWith("/api/vpn") || path.startsWith("/api/servers") || path.startsWith("/api/internal/") || path.startsWith("/link/")

               
                || path.equals("/api/external-identities/{provider}/import")));
    }
}
