package io.aegis.passport.config;

import io.aegis.passport.config.PassportProperties;
import java.nio.file.Paths;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Serves uploaded avatars and client icons from the configured upload directory.
 * Includes validated Passport login backgrounds.
 */
@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final PassportProperties properties;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        for (String directory : new String[] {"avatars", "icons", "backgrounds"}) {
            String location = Paths.get(properties.getUpload().getDir(), directory)
                    .toAbsolutePath().toUri().toString();
            if (!location.endsWith("/")) location += "/";
            registry.addResourceHandler(properties.getUpload().getUrlPrefix() + "/" + directory + "/**")
                    .addResourceLocations(location);
        }
    }
}
