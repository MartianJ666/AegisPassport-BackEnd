package io.aegis.passport.user;
import io.aegis.passport.user.entity.User;
import java.time.Instant; import java.util.List; import java.util.Optional;
import org.springframework.data.domain.Page; import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph; import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying; import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
public interface UserRepository extends JpaRepository<User, Long> {
    @Override @EntityGraph(attributePaths = "roles") Page<User> findAll(Pageable pageable);
    @EntityGraph(attributePaths = "roles") Optional<User> findByUsername(String username);
    @EntityGraph(attributePaths = "roles") Optional<User> findByEmail(String email);
    boolean existsByUsername(String username); boolean existsByEmail(String email);
    @EntityGraph(attributePaths = "roles")
    @Query("SELECT DISTINCT u FROM User u LEFT JOIN u.roles WHERE LOWER(u.username) LIKE LOWER(CONCAT('%',:kw,'%')) OR LOWER(u.email) LIKE LOWER(CONCAT('%',:kw,'%')) OR LOWER(u.nickname) LIKE LOWER(CONCAT('%',:kw,'%'))")
    Page<User> search(@Param("kw") String keyword, Pageable pageable);
    @Modifying @Query("UPDATE User u SET u.enabled = :enabled WHERE u.id IN :ids")
    int batchSetEnabled(@Param("ids") List<Long> ids, @Param("enabled") boolean enabled);
    @Modifying @Query("UPDATE User u SET u.violationCount = u.violationCount + 1 WHERE u.id = :id")
    int incrementViolationCount(@Param("id") Long id);
    @Modifying @Query("UPDATE User u SET u.violationCount = :count, u.bannedUntil = :bannedUntil WHERE u.id = :id")
    int setBanStatus(@Param("id") Long id, @Param("count") int count, @Param("bannedUntil") Instant bannedUntil);
    @Query("SELECT u FROM User u WHERE u.bannedUntil IS NOT NULL AND u.bannedUntil < :now")
    List<User> findExpiredBans(@Param("now") Instant now);
    long countByOrganizationId(Long organizationId);
    @EntityGraph(attributePaths="roles") List<User> findByOrganizationId(Long organizationId);
    @Modifying(clearAutomatically=true,flushAutomatically=true) @Query("UPDATE User u SET u.orgName=:name WHERE u.organizationId=:id")
    int renameOrganization(@Param("id") Long id,@Param("name") String name);
    long countByRoles_Code(String roleCode);
    @EntityGraph(attributePaths = "roles") List<User> findByRoles_Code(String roleCode);
}
