package io.aegis.passport.rbac;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.rbac.annotation.RequirePermission;
import java.util.Comparator;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Minimal role-group choices for app registration and user administration. */
@RestController
@RequestMapping("/api/groups")
@RequiredArgsConstructor
public class GroupController {
    private final RoleRepository roleRepository;

    @GetMapping
    @RequirePermission({PermissionCatalog.CLIENT_WRITE, PermissionCatalog.USER_WRITE})
    public ResponseEntity<ApiResult<List<GroupOption>>> list() {
        var groups = roleRepository.findAll().stream()
                .map(role -> new GroupOption(role.getCode(), role.getName()))
                .sorted(Comparator.comparing(GroupOption::code))
                .toList();
        return ResponseEntity.ok(ApiResult.ok(groups));
    }

    public record GroupOption(String code, String name) {}
}
