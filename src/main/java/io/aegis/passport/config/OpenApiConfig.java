package io.aegis.passport.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** OpenAPI metadata for the built-in Swagger UI at {@code /swagger-ui.html}. */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI passportOpenApi() {
        return new OpenAPI().info(new Info()
                .title("Aegis Passport API")
                .description("Self-hosted OAuth2 / OIDC identity provider with dynamic RBAC")
                .version("1.0.0")
                .license(new License().name("Internal")));
    }
}
