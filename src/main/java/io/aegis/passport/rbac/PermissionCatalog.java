package io.aegis.passport.rbac;
import java.util.List;
import java.util.Set;
public final class PermissionCatalog {
    private PermissionCatalog() {}
    public record PermissionDef(String code, String name, String description, String category) {}
    public record RoleDef(String code, String name, String description, List<String> permissions) {}
    public static final String ORGANIZATION_READ="organization:read";
    public static final String ORGANIZATION_WRITE="organization:write";
    public static final String USER_READ = "user:read";
    public static final String USER_WRITE = "user:write";
    public static final String USER_DELETE = "user:delete";
    public static final String USER_BAN = "user:ban";
    public static final String ROLE_READ = "role:read";
    public static final String ROLE_WRITE = "role:write";
    public static final String ROLE_DELETE = "role:delete";
    public static final String CLIENT_READ = "client:read";
    public static final String CLIENT_WRITE = "client:write";
    public static final String CLIENT_DELETE = "client:delete";
    public static final String APIKEY_ADMIN = "apikey:admin";
    public static final String CONSENT_READ = "consent:read";
    public static final String APIKEY_READ = "apikey:read";
    public static final String ANNOUNCEMENT_WRITE = "announcement:write";
    public static final String AUDIT_READ = "audit:read";
    public static final String SYSTEM_CONFIG_VIEW = "system:config:view";
    public static final String SYSTEM_CONFIG_EDIT = "system:config:edit";
    private static final Set<String> RETIRED_PERMISSIONS = Set.of();
    public static boolean isRetired(String code) { return RETIRED_PERMISSIONS.contains(code); }
    public static final List<PermissionDef> PERMISSIONS = List.of(
            new PermissionDef(ORGANIZATION_READ,"查看组织","查看组织目录、成员与应用访问规则","organization"),
            new PermissionDef(ORGANIZATION_WRITE,"管理组织","新建编辑组织及组织应用门禁","organization"),
            new PermissionDef(USER_READ, "查看用户", "查看用户列表与资料", "user"),
            new PermissionDef(USER_WRITE, "管理用户", "创建编辑用户及角色分配", "user"),
            new PermissionDef(USER_DELETE, "删除用户", "删除用户账号", "user"),
            new PermissionDef(USER_BAN, "封禁用户", "封禁与解封用户账号", "user"),
            new PermissionDef(ROLE_READ, "查看角色", "查看角色与权限目录", "rbac"),
            new PermissionDef(ROLE_WRITE, "管理角色", "创建编辑角色及其权限", "rbac"),
            new PermissionDef(ROLE_DELETE, "删除角色", "删除自定义角色", "rbac"),
            new PermissionDef(CLIENT_READ, "查看应用", "查看OAuth应用", "client"),
            new PermissionDef(CLIENT_WRITE, "管理应用", "创建编辑OAuth应用", "client"),
            new PermissionDef(CLIENT_DELETE, "删除应用", "删除OAuth应用", "client"),
            new PermissionDef(APIKEY_ADMIN, "API密钥管理", "管理所有用户的API密钥", "apikey"),
            new PermissionDef(CONSENT_READ, "查看授权", "查看已授权的OAuth应用", "consent"),
            new PermissionDef(APIKEY_READ, "API密钥", "管理自己的API密钥", "apikey"),
            new PermissionDef(ANNOUNCEMENT_WRITE,"管理公告","发布和管理公告","system"),
            new PermissionDef(AUDIT_READ, "审计日志", "查看与导出审计日志", "system"),
            new PermissionDef(SYSTEM_CONFIG_VIEW, "查看系统配置", "查看邮件与安全等配置", "system"),
            new PermissionDef(SYSTEM_CONFIG_EDIT, "编辑系统配置", "修改邮件与安全等配置", "system")
    );
    public static final List<RoleDef> BUILTIN_ROLES = List.of(
            new RoleDef("admin", "管理员", "拥有全部权限的系统管理员", PERMISSIONS.stream().map(PermissionDef::code).toList()),
            new RoleDef("member", "成员", "可管理OAuth应用API密钥与授权", List.of(CLIENT_READ, CLIENT_WRITE, CLIENT_DELETE, APIKEY_READ, CONSENT_READ)),
            new RoleDef("user", "普通用户", "基础账户能力", List.of())
    );
}
