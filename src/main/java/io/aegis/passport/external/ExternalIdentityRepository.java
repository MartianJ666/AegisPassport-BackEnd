package io.aegis.passport.external;

import io.aegis.passport.external.entity.ExternalIdentity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentity, Long> {
    List<ExternalIdentity> findByUserIdOrderByCreatedAtDesc(Long userId);
    @EntityGraph(attributePaths = "user")
    Optional<ExternalIdentity> findByProviderAndIssuerAndProviderSubject(
            String provider, String issuer, String providerSubject);
}
