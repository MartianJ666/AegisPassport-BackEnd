package io.aegis.passport.client;

import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.file.FileStorageService;
import io.aegis.passport.rbac.RoleRepository;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
public class OAuthClientService {

    private final OAuthClientRepository clientRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final FileStorageService fileStorage;
    private final RoleRepository roleRepository;
    private final io.aegis.passport.organization.OrganizationRepository organizationRepository;

    @Transactional(readOnly = true)
    public List<OAuthClient> getClientsForUser(String username, boolean admin) {
        if (admin) return clientRepo.findAllByOrderByCreatedAtDesc();
        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        return clientRepo.findByOwnerId(user.getId());
    }

    @Transactional
    public OAuthClient create(ClientRequest req, MultipartFile icon,
                              String username, boolean admin) throws Exception {
        validate(req);
        requirePersonalPolicyAdmin(req, null, admin);
        String allowedGroups = normalizeAllowedGroups(req.allowedRoles);
        String allowedOrgs=normalizeOrganizations(req.allowedOrganizations),deniedOrgs=normalizeOrganizations(req.deniedOrganizations);
        User owner = userRepo.findByUsername(username)
                .orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        String clientId = "app_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String rawSecret = UUID.randomUUID().toString().replace("-", "");
        String iconUrl = icon != null && !icon.isEmpty() ? fileStorage.storeClientIcon(icon) : null;
        OAuthClient client = OAuthClient.builder()
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(rawSecret))
                .clientName(req.clientName)
                .clientDescription(req.clientDescription)
                .clientIcon(iconUrl)
                .redirectUris(req.redirectUris)
                .grantTypes(req.grantTypes != null ? req.grantTypes : "authorization_code,refresh_token")
                .scopes(req.scopes != null ? req.scopes : "openid,profile,email")
                .accessTokenTtl(req.accessTokenTtl != null ? req.accessTokenTtl : 900)
                .refreshTokenTtl(req.refreshTokenTtl != null ? req.refreshTokenTtl : 604800)
                .authorizationCodeTtl(req.authorizationCodeTtl != null ? req.authorizationCodeTtl : 300)
                .requirePkce(req.requirePkce == null || req.requirePkce)
                .requireConsent(req.requireConsent == null || req.requireConsent)
                .enabled(req.enabled == null || req.enabled)
                .owner(owner)
                .allowedRoles(allowedGroups)
                .allowedUsers(req.allowedUsers)
                .deniedUsers(req.deniedUsers).organizationRestricted(Boolean.TRUE.equals(req.organizationRestricted)).allowedOrganizations(allowedOrgs).deniedOrganizations(deniedOrgs)
                .build();
        client = clientRepo.save(client);
        // Return the raw secret once on an unmanaged response copy. Mutating the
        // managed entity here would overwrite the BCrypt hash at transaction commit.
        return client.toBuilder().clientSecret(rawSecret).build();
    }

    @Transactional
    public OAuthClient update(String clientId, ClientRequest req, MultipartFile icon,
                              String username, boolean admin) throws Exception {
        validate(req);
        String allowedGroups = normalizeAllowedGroups(req.allowedRoles);
        String allowedOrgs=normalizeOrganizations(req.allowedOrganizations),deniedOrgs=normalizeOrganizations(req.deniedOrganizations);
        OAuthClient client = requireOwned(clientId, username, admin);
        requirePersonalPolicyAdmin(req, client, admin);
        if (StringUtils.hasText(req.clientName)) client.setClientName(req.clientName);
        if (req.clientDescription != null) client.setClientDescription(req.clientDescription);
        if (req.redirectUris != null) client.setRedirectUris(req.redirectUris);
        if (req.grantTypes != null) client.setGrantTypes(req.grantTypes);
        if (req.authorizationCodeTtl != null) client.setAuthorizationCodeTtl(req.authorizationCodeTtl);
        if (req.requirePkce != null) client.setRequirePkce(req.requirePkce);
        if (req.enabled != null) client.setEnabled(req.enabled);
        if (StringUtils.hasText(req.scopes)) client.setScopes(req.scopes);
        if (req.accessTokenTtl != null) client.setAccessTokenTtl(req.accessTokenTtl);
        if (req.refreshTokenTtl != null) client.setRefreshTokenTtl(req.refreshTokenTtl);
        if (req.allowedRoles != null) client.setAllowedRoles(allowedGroups);
        if(req.organizationRestricted!=null)client.setOrganizationRestricted(req.organizationRestricted);
        if(req.allowedOrganizations!=null)client.setAllowedOrganizations(allowedOrgs);
        if(req.deniedOrganizations!=null)client.setDeniedOrganizations(deniedOrgs);
        if (req.allowedUsers != null) {
            client.setAllowedUsers(req.allowedUsers);
            if(client.getAllowedUserExpirations()!=null){
                var expirations=new java.util.HashMap<>(client.getAllowedUserExpirations());
                expirations.keySet().retainAll(ClientAccessPolicy.csv(req.allowedUsers));
                client.setAllowedUserExpirations(expirations);
            }
        }
        if (req.deniedUsers != null) client.setDeniedUsers(req.deniedUsers);
        if (req.requireConsent != null) client.setRequireConsent(req.requireConsent);
        if (icon != null && !icon.isEmpty()) client.setClientIcon(fileStorage.storeClientIcon(icon));
        return clientRepo.save(client);
    }

    @Transactional
    public void delete(String clientId, String username, boolean admin) {
        OAuthClient client = requireOwned(clientId, username, admin);
        clientRepo.delete(client);
    }

    private OAuthClient requireOwned(String clientId, String username, boolean admin) {
        OAuthClient client = clientRepo.findForPolicyUpdate(clientId)
                .orElseThrow(() -> BusinessException.of(ErrorCode.CLIENT_NOT_FOUND));
        if (!admin && (client.getOwner() == null || !client.getOwner().getUsername().equals(username))) {
            throw BusinessException.of(ErrorCode.FORBIDDEN);
        }
        return client;
    }

    private static void requirePersonalPolicyAdmin(ClientRequest req, OAuthClient existing, boolean admin) {
        if(admin)return;
        if((req.allowedUsers()!=null && !ClientAccessPolicy.csv(req.allowedUsers()).equals(ClientAccessPolicy.csv(existing==null?null:existing.getAllowedUsers())))
            || (req.deniedUsers()!=null && !ClientAccessPolicy.csv(req.deniedUsers()).equals(ClientAccessPolicy.csv(existing==null?null:existing.getDeniedUsers()))))
            throw BusinessException.of(ErrorCode.FORBIDDEN,"个人放行与禁止只能由管理员授予或撤销");
    }
    private String normalizeAllowedGroups(String value) {
        if (value == null) return null;
        var groups = Arrays.stream(value.split(",")).map(String::trim)
                .filter(StringUtils::hasText).distinct().sorted().toList();
        String normalized = String.join(",", groups);
        if (normalized.length() > 300) {
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "允许访问的组过多");
        }
        for (String code : groups) {
            if (!roleRepository.existsByCode(code)) {
                throw BusinessException.of(ErrorCode.ROLE_NOT_FOUND, "所属组不存在：" + code);
            }
        }
        return normalized;
    }

    private String normalizeOrganizations(String value) {
        if(value==null)return null;
        var ids=ClientAccessPolicy.csv(value);
        String normalized=String.join(",",ids);
        if(normalized.length()>1000)throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织规则数量超过限制");
        for(String id:ids){
            try{if(!organizationRepository.existsById(Long.parseLong(id)))throw new IllegalArgumentException();}
            catch(IllegalArgumentException e){throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织不存在，请刷新组织列表后重新选择");}
        }
        return normalized;
    }
    private static void validate(ClientRequest req) {
        for (Integer ttl : new Integer[] {req.accessTokenTtl, req.refreshTokenTtl, req.authorizationCodeTtl}) {
            if (ttl != null && ttl <= 0) throw BusinessException.of(ErrorCode.BAD_REQUEST, "令牌有效期必须为正整数秒");
        }
        if (req.clientName != null && (!StringUtils.hasText(req.clientName) || req.clientName.length() > 100))
            throw BusinessException.of(ErrorCode.BAD_REQUEST, "应用名称需 1-100 个字符");
        if (req.grantTypes != null) {
            var supported = java.util.Set.of("authorization_code", "refresh_token", "client_credentials");
            if (!StringUtils.hasText(req.grantTypes) || Arrays.stream(req.grantTypes.split(",", -1)).anyMatch(g -> !supported.contains(g.trim())))
                throw BusinessException.of(ErrorCode.BAD_REQUEST, "不支持的授权类型");
        }
    }

    public record ClientRequest(
            String clientName, String clientDescription, String redirectUris,
            String grantTypes, String scopes, Integer accessTokenTtl,
            Integer refreshTokenTtl, Integer authorizationCodeTtl,
            Boolean requirePkce, Boolean requireConsent,
            String allowedRoles, String allowedUsers, String deniedUsers, Boolean enabled,
            Boolean organizationRestricted,String allowedOrganizations,String deniedOrganizations) {
        public ClientRequest(String clientName,String clientDescription,String redirectUris,String grantTypes,String scopes,
                Integer accessTokenTtl,Integer refreshTokenTtl,Integer authorizationCodeTtl,Boolean requirePkce,Boolean requireConsent,
                String allowedRoles,String allowedUsers,String deniedUsers,Boolean enabled) {
            this(clientName,clientDescription,redirectUris,grantTypes,scopes,accessTokenTtl,refreshTokenTtl,authorizationCodeTtl,
                requirePkce,requireConsent,allowedRoles,allowedUsers,deniedUsers,enabled,null,null,null);
        }
        public ClientRequest(String clientName, String clientDescription, String redirectUris,
                String grantTypes, String scopes, Integer accessTokenTtl, Integer refreshTokenTtl,
                Integer authorizationCodeTtl, Boolean requirePkce, Boolean requireConsent,
                String allowedRoles, String allowedUsers, String deniedUsers) {
            this(clientName, clientDescription, redirectUris, grantTypes, scopes, accessTokenTtl,
                    refreshTokenTtl, authorizationCodeTtl, requirePkce, requireConsent,
                    allowedRoles, allowedUsers, deniedUsers, null);
        }
    }
}
