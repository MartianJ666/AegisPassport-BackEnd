package io.aegis.passport.security;

import io.aegis.passport.config.PassportProperties;
import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.rbac.RoleRepository;
import io.aegis.passport.rbac.entity.Role;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Creates the bootstrap admin account on the very first startup if no user
 * with the {@code admin} role exists. The password is taken from the env var
 * {@code BOOTSTRAP_ADMIN_PASSWORD}; if blank a random one is generated and
 * printed once to the log.
 */
@Slf4j
@Component
@Order(20)          // runs after RbacInitializer (order 10)
@RequiredArgsConstructor
public class BootstrapAdminInitializer {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final PassportProperties props;

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void init() {
        if (userRepo.countByRoles_Code("admin") > 0) {
            return; // at least one admin exists
        }
        Role adminRole = roleRepo.findByCode("admin")
                .orElseThrow(() -> new IllegalStateException("内置 admin 角色未找到"));
        String username = props.getBootstrapAdmin().getUsername();
        String password = props.getBootstrapAdmin().getPassword();
        boolean generated = false;
        if (!StringUtils.hasText(password)) {
            password = UUID.randomUUID().toString().replace("-", "").substring(0, 20);
            generated = true;
        }
        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        User admin = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .primaryRole("admin")
                .roles(roles)
                .enabled(true)
                .build();
        userRepo.save(admin);
        if (generated) {
            log.warn("╔══════════════════════════════════════════════════════════════╗");
            log.warn("║  Bootstrap admin created — CHANGE THIS PASSWORD IMMEDIATELY  ║");
            log.warn("║  username: {}                                           ║", username);
            log.warn("║  password: {}                        ║", password);
            log.warn("╚══════════════════════════════════════════════════════════════╝");
        } else {
            log.info("[Bootstrap] 管理员账号已创建 username={}", username);
        }
    }
}
