package io.aegis.passport.organization;
import io.aegis.passport.organization.entity.Organization;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
public interface OrganizationRepository extends JpaRepository<Organization,Long> {
    List<Organization> findAllByOrderByNameAsc();
    boolean existsByNameIgnoreCase(String name);
    boolean existsByNameIgnoreCaseAndIdNot(String name,Long id);
}
