package io.aegis.passport.announcement;

import io.aegis.passport.announcement.entity.Announcement;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AnnouncementRepository extends JpaRepository<Announcement, Long> {

    List<Announcement> findAllByOrderByCreatedAtDesc();

    /** Time-windowed, global-only announcements (public / web-home scope). */
    @Query("SELECT a FROM Announcement a WHERE a.enabled = true "
            + "AND (a.startTime IS NULL OR a.startTime <= :now) "
            + "AND (a.endTime IS NULL OR a.endTime >= :now) "
            + "AND (a.targetClients IS NULL OR a.targetClients = '') "
            + "ORDER BY a.createdAt DESC")
    List<Announcement> findActive(@Param("now") Instant now);

    /**
     * Time-windowed announcements visible to one OAuth client: global ones plus
     * ones whose comma-separated target list contains {@code clientId}.
     */
    @Query("SELECT a FROM Announcement a WHERE a.enabled = true "
            + "AND (a.startTime IS NULL OR a.startTime <= :now) "
            + "AND (a.endTime IS NULL OR a.endTime >= :now) "
            + "AND (a.targetClients IS NULL OR a.targetClients = '' "
            + "     OR CONCAT(',', a.targetClients, ',') LIKE CONCAT('%,', :clientId, ',%')) "
            + "ORDER BY a.createdAt DESC")
    List<Announcement> findActiveForClient(@Param("now") Instant now, @Param("clientId") String clientId);

    /**
     * Archive view for one OAuth client: same audience as
     * {@link #findActiveForClient} but without the end-time upper bound, so
     * already-expired announcements stay visible in the client's announcement
     * centre. Disabled and not-yet-published items are excluded.
     */
    @Query("SELECT a FROM Announcement a WHERE a.enabled = true "
            + "AND (a.startTime IS NULL OR a.startTime <= :now) "
            + "AND (a.targetClients IS NULL OR a.targetClients = '' "
            + "     OR CONCAT(',', a.targetClients, ',') LIKE CONCAT('%,', :clientId, ',%')) "
            + "ORDER BY a.createdAt DESC")
    List<Announcement> findHistoryForClient(@Param("now") Instant now, @Param("clientId") String clientId);
}
