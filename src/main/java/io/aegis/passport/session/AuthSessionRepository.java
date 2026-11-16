package io.aegis.passport.session;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface AuthSessionRepository extends JpaRepository<AuthSession, String> {
    @Query("SELECT COUNT(s) > 0 FROM AuthSession s WHERE s.id=:id AND s.user.id=:uid AND s.revokedAt IS NULL AND s.expiresAt>:now")
    boolean isActive(@Param("id") String id,@Param("uid") Long userId,@Param("now") Instant now);
    List<AuthSession> findByUser_IdOrderByLastSeenAtDesc(Long userId);
    @Modifying
    @Query("UPDATE AuthSession s SET s.revokedAt = :now, s.revokedReason = :reason, s.revokedBy = :actor WHERE s.user.id = :userId AND s.revokedAt IS NULL AND s.expiresAt > :now AND s.id <> :exceptId")
    int revokeActiveForUserExcept(@Param("userId") Long userId, @Param("exceptId") String exceptId, @Param("now") Instant now, @Param("reason") String reason, @Param("actor") String actor);
    @Modifying
    @Query("UPDATE AuthSession s SET s.revokedAt = :now, s.revokedReason = :reason, s.revokedBy = :actor WHERE s.revokedAt IS NULL AND s.expiresAt > :now AND s.id <> :exceptId")
    int revokeAllExcept(@Param("exceptId") String exceptId, @Param("now") Instant now, @Param("reason") String reason, @Param("actor") String actor);
    @Modifying
    @Query("UPDATE AuthSession s SET s.revokedAt = :now, s.revokedReason = :reason, s.revokedBy = :actor WHERE s.id IN :ids AND s.user.id = :userId AND s.revokedAt IS NULL")
    int revokeOwned(@Param("userId") Long userId, @Param("ids") Collection<String> ids, @Param("now") Instant now, @Param("reason") String reason, @Param("actor") String actor);
}
