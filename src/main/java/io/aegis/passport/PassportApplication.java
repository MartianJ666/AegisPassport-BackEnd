package io.aegis.passport;
import org.springframework.boot.SpringApplication; import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableAsync; import org.springframework.scheduling.annotation.EnableScheduling;
@SpringBootApplication @EnableAsync @EnableScheduling @EnableConfigurationProperties(io.aegis.passport.config.PassportProperties.class)
public class PassportApplication {
    public static void main(String[] args) { SpringApplication.run(PassportApplication.class, args); }
}
