package io.aegis.passport.client;

import io.aegis.passport.client.entity.OAuthClient;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, Long> {

    @EntityGraph(attributePaths = "owner")
    Optional<OAuthClient> findByClientId(String clientId);

    boolean existsByClientId(String clientId);

    @EntityGraph(attributePaths = "owner")
    List<OAuthClient> findByOwnerId(Long ownerId);

    @EntityGraph(attributePaths = "owner")
    List<OAuthClient> findAllByOrderByCreatedAtDesc();
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("SELECT c FROM OAuthClient c WHERE c.clientId=:clientId")
    java.util.Optional<OAuthClient> findForPolicyUpdate(@org.springframework.data.repository.query.Param("clientId") String clientId);
}
