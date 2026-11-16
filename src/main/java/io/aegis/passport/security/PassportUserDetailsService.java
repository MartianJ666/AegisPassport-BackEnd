package io.aegis.passport.security;

import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Loads a {@link PassportUserPrincipal} for Spring Security authentication.
 * Used by both form-login (OAuth2 consent) and the JWT filter.
 */
@Service
@RequiredArgsConstructor
public class PassportUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionResolver permissionResolver;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseGet(() -> userRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("用户不存在：" + username)));
        // Effective permission codes are loaded eagerly and baked into the principal
        // so every subsequent authority check is just a Set.contains() — no extra DB hits.
        var permissions = permissionResolver.effectivePermissions(user.getId());
        var roles = permissionResolver.roleCodes(user.getId());
        return new PassportUserPrincipal(user, roles, permissions);
    }
}
