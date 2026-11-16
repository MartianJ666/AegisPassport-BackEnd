package io.aegis.passport.oauth;

import io.aegis.passport.oauth.entity.SigningKey;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SigningKeyRepository extends JpaRepository<SigningKey, Long> {

    List<SigningKey> findByActiveTrueOrderByCreatedAtDesc();
}
