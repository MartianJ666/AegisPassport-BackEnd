package io.aegis.passport.oauth;

import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Component;

/**
 * Builds the OIDC {@link OidcUserInfo} claims map for the {@code /userinfo}
 * endpoint and the ID token customizer. Includes {@code role} and
 * {@code permissions} claims when the {@code profile} scope was granted so
 * downstream applications can make RBAC decisions without extra API calls.
 */
@Component
@RequiredArgsConstructor
public class OidcUserInfoMapper {

    private final UserRepository userRepository;
    private final PermissionResolver permissionResolver;

    public OidcUserInfo map(String username, Set<String> scopes) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在：" + username));

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", String.valueOf(user.getId()));
        claims.put("preferred_username", user.getUsername());
        claims.put("name", user.getNickname() != null ? user.getNickname() : user.getUsername());

        if (scopes.contains("profile")) {
            claims.put("picture", user.getAvatar());
            claims.put("role", user.getPrimaryRole());
            if(user.getOrgName()!=null)claims.put("org_name", user.getOrgName());
            Set<String> perms = permissionResolver.effectivePermissions(user.getId());
            claims.put("permissions", perms);
        }
        if(scopes.contains("groups"))claims.put("groups",permissionResolver.roleCodes(user.getId()).stream().sorted().toList());
        if(scopes.contains("organization") && user.getOrganizationId()!=null){
            claims.put("organization_id",user.getOrganizationId());claims.put("organization_name",user.getOrgName());
        }
        if (scopes.contains("email")) {
            claims.put("email", user.getEmail());
            claims.put("email_verified", user.getEmail() != null && user.isEmailVerified());
        }
        return new OidcUserInfo(claims);
    }
}
