package io.aegis.passport.security;

import io.aegis.passport.user.entity.User;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * The authenticated principal placed in the security context. Wraps the
 * {@link User} id and username and exposes role codes as {@code ROLE_*}
 * authorities plus raw permission codes as authorities, so both Spring's
 * {@code hasRole} and our own {@code @RequirePermission} can read from one place.
 */
public class PassportUserPrincipal implements UserDetails {

    private final Long id;
    private final String username;
    private final String password;
    private final boolean enabled;
    private final boolean locked;
    private final boolean needsSetup;
    private final List<GrantedAuthority> authorities;

    public PassportUserPrincipal(User user, Collection<String> roleCodes,
                                 Collection<String> permissionCodes) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.enabled = user.isEnabled();
        this.locked = user.isLocked();
        this.needsSetup = user.isNeedsSetup();
        // Role codes are supplied explicitly (never read from the lazy
        // user.getRoles() association) so this principal can be built outside a
        // JPA transaction — e.g. in the stateless JWT filter.
        Stream<String> roleAuthorities = roleCodes.stream()
                .map(c -> "ROLE_" + c.toUpperCase());
        this.authorities = new ArrayList<>(Stream.concat(roleAuthorities, permissionCodes.stream())
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .toList());
        // Spring Security 7.1's JwtGenerator derives the OIDC auth_time claim from a
        // FactorGrantedAuthority in the principal's authorities; without one, ID-token
        // generation throws "authenticationTime cannot be null" and the /oauth2/token
        // endpoint returns server_error (SSO login breaks). issuedAt ≈ load/login time.
        this.authorities.add(FactorGrantedAuthority
                .withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(Instant.now())
                .build());
    }

    public Long getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public boolean isNeedsSetup() {
        return needsSetup;
    }
}
