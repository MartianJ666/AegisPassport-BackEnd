package io.aegis.passport.user;
import io.aegis.passport.auth.dto.AuthDtos.ChangePasswordRequest;
import io.aegis.passport.auth.dto.AuthDtos.RegisterRequest;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.rbac.PermissionResolver;
import io.aegis.passport.rbac.RoleRepository;
import io.aegis.passport.rbac.entity.Role;
import io.aegis.passport.user.dto.UserDtos.*;
import io.aegis.passport.user.entity.User;
import java.time.Instant; import java.util.HashSet; import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
@Service @RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final io.aegis.passport.organization.OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;
    private final PermissionResolver permissionResolver;
    private final io.aegis.passport.auth.VerificationCodeService verificationCodes;
    private final org.springframework.jdbc.core.JdbcTemplate jdbc;
    private final org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizations;
    @Transactional(readOnly = true)
    public UserView getByUsername(String username) {
        User user = require(username);
        UserView view = UserView.from(user);
        view.setPermissions(permissionResolver.effectivePermissions(user.getId()));
        return view;
    }
    @Transactional
    public User registerUser(RegisterRequest req, boolean adminContext) {
        io.aegis.passport.security.PasswordPolicy.validate(req.getPassword());
        String name = req.getUsername() == null ? "" : req.getUsername().trim();
        if (name.length() < 3 || name.length() > 50 || name.chars().anyMatch(Character::isWhitespace))
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "用户名需 3-50 个字符，且不能包含空白字符");
        req.setUsername(name);
        if (StringUtils.hasText(req.getEmail())) req.setEmail(req.getEmail().trim().toLowerCase(java.util.Locale.ROOT));
        if (userRepository.existsByUsername(req.getUsername())) throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS, "用户名已存在");
        if (StringUtils.hasText(req.getEmail()) && userRepository.existsByEmail(req.getEmail())) throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS, "邮箱已被占用");
        Set<Role> roles;
        String roleCode;
        if (adminContext && req.getGroups() != null) {
            roles = resolveGroups(req.getGroups());
            roleCode = roles.iterator().next().getCode();
        } else {
            roleCode = adminContext && StringUtils.hasText(req.getRole()) ? req.getRole() : "user";
            Role role = roleRepository.findByCode(roleCode).orElseGet(() -> roleRepository.findByCode("user").orElseThrow(() -> BusinessException.of(ErrorCode.ROLE_NOT_FOUND)));
            roles = new HashSet<>(); roles.add(role);
        }
        String email = StringUtils.hasText(req.getEmail()) ? req.getEmail() : null;
        if (!adminContext && req.getOrganizationId()!=null)throw BusinessException.of(ErrorCode.FORBIDDEN);
        if(StringUtils.hasText(req.getOrgName()) && req.getOrganizationId()==null)throw BusinessException.of(ErrorCode.BAD_REQUEST,"请从已创建的组织中选择");
        User user = User.builder().username(req.getUsername()).password(passwordEncoder.encode(req.getPassword())).email(email).emailVerified(!adminContext && email != null).phone(req.getPhone()).orgName(null).nickname(req.getNickname()).primaryRole(roleCode).roles(roles).enabled(!adminContext || req.getEnabled()==null || req.getEnabled()).build();
        applyOrganization(user,req.getOrganizationId());
        clearPrincipalArtifacts(name);
        return userRepository.save(user);
    }

    @Transactional
    public User changeUsername(String oldUsername, String newUsername) {
        String username = newUsername == null ? "" : newUsername.trim();
        if (username.length() < 3 || username.length() > 50) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "用户名需 3-50 个字符");
        }
        if (username.chars().anyMatch(Character::isWhitespace)) throw BusinessException.of(ErrorCode.BAD_REQUEST, "用户名不能包含空白字符");
        User user = require(oldUsername);
        User owner = userRepository.findByUsername(username).orElse(null);
        if (owner != null && !owner.getId().equals(user.getId())) {
            throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS, "用户名已被占用");
        }
        if (username.equals(oldUsername)) return user;
        clearPrincipalArtifacts(username); // orphaned rows from a previously deleted account
        jdbc.update("UPDATE oauth_consents SET principal_name=? WHERE principal_name=?", username, oldUsername);
        jdbc.update("UPDATE oauth_client_accounts SET owner_username=? WHERE owner_username=?", username, oldUsername);
        jdbc.update("UPDATE oauth_client_accounts SET app_username=? WHERE app_username=?", username, oldUsername);
        revokeOAuth(oldUsername);
        user.setUsername(username);
        userRepository.save(user);
        permissionResolver.evict(user.getId());
        return user;
    }

    /** Creates a generated local shell only after a provider identity was verified server-side. */
    @Transactional
    public User createExternalUser(String verifiedEmail, String nickname, String avatar) {
        String email = StringUtils.hasText(verifiedEmail) ? verifiedEmail.trim().toLowerCase(java.util.Locale.ROOT) : null;
        if (email != null && userRepository.existsByEmail(email)) {
            email = null;
        }
        Role role = roleRepository.findByCode("user")
                .orElseThrow(() -> BusinessException.of(ErrorCode.ROLE_NOT_FOUND));
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        String username;
        do {
            username = "ext-" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 20);
        } while (userRepository.existsByUsername(username));
        String placeholderPassword = java.util.UUID.randomUUID().toString().replace("-", "")
                + java.util.UUID.randomUUID().toString().replace("-", "");
        User user = User.builder().username(username).password(passwordEncoder.encode(placeholderPassword))
                .email(email).emailVerified(email != null).nickname(StringUtils.hasText(nickname) ? nickname.trim() : null)
                .avatar(StringUtils.hasText(avatar) ? avatar.trim() : null)
                .primaryRole("user").roles(roles).enabled(true).needsSetup(true).build();
        return userRepository.save(user);
    }

    @Transactional
    public UserView updateProfile(String username, UpdateProfileRequest req) {
        if(req.getOrganizationId()!=null)throw BusinessException.of(ErrorCode.FORBIDDEN,"所属组织由管理员分配");
        User user = require(username);
        if (req.getNickname() != null) user.setNickname(optional(req.getNickname()));
        if (req.getPhone() != null) user.setPhone(optional(req.getPhone()));
        if (req.getOrgName() != null) {
            if (!java.util.Objects.equals(optional(req.getOrgName()),user.getOrgName()))
                throw BusinessException.of(ErrorCode.FORBIDDEN,"所属组织由管理员分配，请联系管理员调整");
        }
        if (req.getEmail() != null) {
            String email = optional(req.getEmail());
            if (email != null) email = email.toLowerCase(java.util.Locale.ROOT);
            if (!java.util.Objects.equals(email, user.getEmail())) {
                if (email != null && userRepository.existsByEmail(email)) throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS, "邮箱已被占用");
                user.setEmail(email);
                user.setEmailVerified(false);
            }
            if (StringUtils.hasText(req.getVerificationCode())) {
                if (email == null || !verificationCodes.verify(email, req.getVerificationCode()))
                    throw BusinessException.of(ErrorCode.VERIFICATION_CODE_INVALID);
                user.setEmailVerified(true);
            }
        }
        return UserView.from(userRepository.save(user));
    }
    @Transactional
    public void changePassword(String username, ChangePasswordRequest req) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        if (!passwordEncoder.matches(req.getOldPassword(), user.getPassword())) throw BusinessException.of(ErrorCode.INVALID_CREDENTIALS, "原密码错误");
        io.aegis.passport.security.PasswordPolicy.validate(req.getNewPassword());
        user.setPassword(passwordEncoder.encode(req.getNewPassword())); userRepository.save(user);
    }
    @Transactional
    public void updateAvatar(String username, String avatarUrl, String md5) {
        User user = require(username); user.setAvatar(avatarUrl); user.setAvatarMd5(md5); userRepository.save(user);
    }
    @Transactional
    public void recordLogin(String username) {
        userRepository.findByUsername(username).ifPresent(u -> { u.setLastLoginAt(Instant.now()); userRepository.save(u); });
    }
    @Transactional
    public UserView adminUpdateUser(Long id, AdminUpdateUserRequest req, PasswordEncoder encoder) {
        if (req.getPassword() != null) throw BusinessException.of(ErrorCode.BAD_REQUEST, "请使用专用的重置密码功能修改密码");
        User user = userRepository.findById(id).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        if(req.getOrganizationId()!=null)applyOrganization(user,req.getOrganizationId());
        if (req.getGroups() != null) {
            Set<Role> groups = resolveGroups(req.getGroups());
            user.setRoles(groups);
            user.setPrimaryRole(groups.iterator().next().getCode());
        }
        if (req.getNickname() != null) user.setNickname(optional(req.getNickname()));
        if (req.getPhone() != null) user.setPhone(optional(req.getPhone()));
        if (req.getOrgName() != null) {
            if (!java.util.Objects.equals(optional(req.getOrgName()),user.getOrgName()))
                throw BusinessException.of(ErrorCode.FORBIDDEN,"所属组织由管理员分配，请联系管理员调整");
        }
        if (req.getEmail() != null && !java.util.Objects.equals(optional(req.getEmail()), user.getEmail())) {
            String email=optional(req.getEmail());
            if(email!=null) {
                email=email.toLowerCase(java.util.Locale.ROOT);
                if(email.chars().anyMatch(Character::isWhitespace) || !email.matches("^[^@]+@[^@]+[.][^@]+$") || email.length()>100)
                    throw BusinessException.of(ErrorCode.BAD_REQUEST,"邮箱格式不正确");
                var owner=userRepository.findByEmail(email).orElse(null);
                if(owner!=null && !owner.getId().equals(id))throw BusinessException.of(ErrorCode.USER_ALREADY_EXISTS,"邮箱已被占用");
            }
            user.setEmail(email); user.setEmailVerified(false);
        }
        if (req.getEnabled() != null) user.setEnabled(req.getEnabled());
        if (req.getLocked() != null) user.setLocked(req.getLocked());
        userRepository.save(user); permissionResolver.evict(user.getId());
        return UserView.from(user);
    }
    @Transactional
    public void assignRoles(Long userId, Set<String> roleCodes) {
        User user = userRepository.findById(userId).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        Set<Role> roles = resolveGroups(roleCodes);
        user.setRoles(roles);
        if (!roles.isEmpty()) user.setPrimaryRole(roles.iterator().next().getCode());
        userRepository.save(user); permissionResolver.evict(userId);
    }
    @Transactional
    public int batchSetEnabled(java.util.List<Long> ids, boolean enabled) {
        int n = userRepository.batchSetEnabled(ids, enabled);
        ids.forEach(permissionResolver::evict); return n;
    }
    @Transactional
    public void batchDelete(java.util.List<Long> ids, String operatorUsername) {
        for (Long id : ids) {
            User user = userRepository.findById(id).orElse(null);
            if (user != null && !user.getUsername().equals(operatorUsername)) {
                clearPrincipalArtifacts(user.getUsername());
                revokeOAuth(user.getUsername());
                permissionResolver.evict(id); userRepository.delete(user);
            }
        }
    }
    public boolean existsByUsername(String username) { return userRepository.existsByUsername(username); }
    private void revokeOAuth(String username) {
        if (authorizations instanceof io.aegis.passport.oauth.AuditedOAuth2AuthorizationService audited) audited.revokeByPrincipal(username, null);
    }
    private void clearPrincipalArtifacts(String username) {
        jdbc.update("DELETE FROM oauth_consents WHERE principal_name=?", username);
        jdbc.update("DELETE FROM oauth_client_accounts WHERE owner_username=? OR app_username=?", username, username);
    }
    public UserRepository getUserRepository() { return userRepository; }
    private static String optional(String s) { return StringUtils.hasText(s) ? s.trim() : null; }
    private Set<Role> resolveGroups(Set<String> codes) {
        if (codes.isEmpty() || codes.stream().anyMatch(code -> !StringUtils.hasText(code))) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "请选择至少一个有效的所属组");
        }
        Set<Role> roles = new java.util.LinkedHashSet<>();
        codes.stream().map(String::trim).distinct().sorted().forEach(code ->
                roles.add(roleRepository.findByCode(code).orElseThrow(() ->
                        BusinessException.of(ErrorCode.ROLE_NOT_FOUND, "所属组不存在：" + code))));
        return roles;
    }
    private void applyOrganization(User user,Long id) {
        if(id==null)return;
        if(id==0){user.setOrganizationId(null);user.setOrgName(null);return;}
        var org=organizationRepository.findById(id).orElseThrow(()->BusinessException.of(ErrorCode.BAD_REQUEST,"组织不存在，请先在组织管理页创建后再选择"));
        user.setOrganizationId(org.getId());user.setOrgName(org.getName());
    }
    private User require(String username) { return userRepository.findByUsername(username).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND)); }
}
