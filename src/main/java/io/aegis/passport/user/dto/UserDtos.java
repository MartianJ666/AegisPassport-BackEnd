package io.aegis.passport.user.dto;
import io.aegis.passport.user.entity.User;
import java.time.Instant; import java.util.Set;
import lombok.Builder; import lombok.Data;
public final class UserDtos {
    private UserDtos() {}
    @Data @Builder
    public static class UserView {
        private Long id; private String username; private String email; private String phone;
        private String nickname; private String avatar; private String avatarMd5; private String orgName; private Long organizationId;
        private boolean emailVerified; private String primaryRole; private Set<String> roles; private Set<String> permissions;
        private boolean enabled; private boolean locked; private int violationCount;
        private Instant bannedUntil; private Instant createdAt; private Instant updatedAt;
        private Instant lastLoginAt; private boolean banned; private boolean needsSetup;
        public static UserView from(User u) {
            Set<String> rc = new java.util.HashSet<>();
            if (u.getRoles() != null) u.getRoles().forEach(r -> rc.add(r.getCode()));
            return UserView.builder().id(u.getId()).username(u.getUsername()).email(u.getEmail())
                    .phone(u.getPhone()).nickname(u.getNickname()).avatar(u.getAvatar())
                    .avatarMd5(u.getAvatarMd5()).orgName(u.getOrgName()).organizationId(u.getOrganizationId())
                    .emailVerified(u.isEmailVerified()).primaryRole(u.getPrimaryRole()).roles(rc)
                    .enabled(u.isEnabled()).locked(u.isLocked())
                    .violationCount(u.getViolationCount()).bannedUntil(u.getBannedUntil())
                    .banned(u.isBanned()).needsSetup(u.isNeedsSetup())
                    .createdAt(u.getCreatedAt()).updatedAt(u.getUpdatedAt()).lastLoginAt(u.getLastLoginAt())
                    .build();
        }
    }
    @Data public static class UpdateProfileRequest { private String nickname; private String phone; private String orgName; private Long organizationId; @jakarta.validation.constraints.Email @jakarta.validation.constraints.Size(max=100) private String email; private String verificationCode; }
    @Data public static class ChangeUsernameRequest { private String username; }
    @Data public static class AdminUpdateUserRequest { private String nickname; private String phone; private String orgName; private Long organizationId; private String email; private String password; private Boolean enabled; private Boolean locked; private Set<String> groups; }
    @Data public static class BanUserRequest { private boolean ban; private int durationHours; }
    @Data public static class BatchEnableRequest { private java.util.List<Long> userIds; private boolean enabled; }
    @Data public static class BatchRoleRequest { private java.util.List<Long> userIds; private String roleCode; }
    @Data public static class BatchDeleteRequest { private java.util.List<Long> userIds; }
}
