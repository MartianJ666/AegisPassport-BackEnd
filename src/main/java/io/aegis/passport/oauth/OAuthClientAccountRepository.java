package io.aegis.passport.oauth;

import io.aegis.passport.oauth.entity.OAuthClientAccount;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientAccountRepository extends JpaRepository<OAuthClientAccount, Long> {

    Optional<OAuthClientAccount> findByClientIdAndOwnerUsername(String clientId, String ownerUsername);
}
