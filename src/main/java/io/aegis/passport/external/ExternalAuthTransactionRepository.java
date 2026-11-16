package io.aegis.passport.external;

import io.aegis.passport.external.entity.ExternalAuthTransaction;
import java.time.Instant;
import java.util.Optional;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ExternalAuthTransactionRepository extends JpaRepository<ExternalAuthTransaction, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = "user")
    @Query("select t from ExternalAuthTransaction t where t.id = :id")
    Optional<ExternalAuthTransaction> findLockedById(@Param("id") String id);
    long deleteByExpiresAtBefore(Instant cutoff);
}
