package io.aegis.passport.email;

import io.aegis.passport.email.entity.EmailConfig;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailConfigRepository extends JpaRepository<EmailConfig, Long> {

    Optional<EmailConfig> findTopByOrderByIdAsc();
}
