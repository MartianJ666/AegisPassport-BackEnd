package io.aegis.passport.consent;

import io.aegis.passport.consent.entity.OAuthConsent;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthConsentRepository extends JpaRepository<OAuthConsent, Long> {

    Optional<OAuthConsent> findByClientIdAndPrincipalName(String clientId, String principalName);

    List<OAuthConsent> findByPrincipalName(String principalName);

    void deleteByClientIdAndPrincipalName(String clientId, String principalName);
}
