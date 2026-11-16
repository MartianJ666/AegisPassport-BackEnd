package io.aegis.passport.apikey;

import io.aegis.passport.apikey.entity.ApiKey;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {

    Optional<ApiKey> findByApiKey(String apiKey);

    List<ApiKey> findByOwnerIdOrderByCreatedAtDesc(Long ownerId);

    Optional<ApiKey> findByIdAndOwnerId(Long id, Long ownerId);

    @EntityGraph(attributePaths = "owner")
    List<ApiKey> findAllByOrderByCreatedAtDesc();
}
