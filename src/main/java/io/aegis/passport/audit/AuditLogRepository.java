package io.aegis.passport.audit;

import io.aegis.passport.audit.entity.AuditLog;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long>,
        JpaSpecificationExecutor<AuditLog> {

    @Query("SELECT DISTINCT a.module FROM AuditLog a ORDER BY a.module")
    List<String> findDistinctModules();

    @Query("SELECT DISTINCT a.action FROM AuditLog a ORDER BY a.action")
    List<String> findDistinctActions();

    long countBySuccess(boolean success);

    long countByTimestampAfter(Instant since);

    /** Single bulk DELETE for archiving; avoids loading the matched rows into memory. */
    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoff")
    int deleteByTimestampBefore(@Param("cutoff") Instant cutoff);
}
