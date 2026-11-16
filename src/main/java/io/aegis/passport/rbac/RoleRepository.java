package io.aegis.passport.rbac;

import io.aegis.passport.rbac.entity.Role;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @EntityGraph(attributePaths = "permissions")
    Optional<Role> findByCode(String code);

    @EntityGraph(attributePaths = "permissions")
    Set<Role> findByCodeIn(Set<String> codes);

    boolean existsByCode(String code);
}
