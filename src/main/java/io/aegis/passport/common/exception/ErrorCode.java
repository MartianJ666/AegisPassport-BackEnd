package io.aegis.passport.common.exception;

import lombok.Getter;

/**
 * Catalog of business error codes. {@code status} is the HTTP status returned
 * to the client; {@code code} is a stable machine-readable identifier so the
 * frontend can branch on specific failures.
 */
@Getter
public enum ErrorCode {

    // Generic
    BAD_REQUEST(400, "BAD_REQUEST", "请求参数有误"),
    UNAUTHORIZED(401, "UNAUTHORIZED", "未认证或登录已失效"),
    FORBIDDEN(403, "FORBIDDEN", "无权限执行该操作"),
    NOT_FOUND(404, "NOT_FOUND", "资源不存在"),
    CONFLICT(409, "CONFLICT", "资源冲突"),
    RATE_LIMITED(429, "RATE_LIMITED", "请求过于频繁"),
    INTERNAL_ERROR(500, "INTERNAL_ERROR", "服务器内部错误"),

    // Auth
    INVALID_CREDENTIALS(400, "INVALID_CREDENTIALS", "用户名或密码错误"),
    LOGIN_SERVICE_UNAVAILABLE(503, "LOGIN_SERVICE_UNAVAILABLE", "登录验证服务暂时不可用，请稍后重试"),
    LOGIN_SESSION_UNAVAILABLE(503, "LOGIN_SESSION_UNAVAILABLE", "账号验证已通过，但无法建立登录会话，请稍后重试"),
    ACCOUNT_LOCKED(429, "ACCOUNT_LOCKED", "账户已锁定，请稍后再试"),
    ACCOUNT_DISABLED(403, "ACCOUNT_DISABLED", "账户已被禁用"),
    VERIFICATION_CODE_INVALID(400, "VERIFICATION_CODE_INVALID", "验证码无效或已过期"),
    EMAIL_NOT_CONFIGURED(400, "EMAIL_NOT_CONFIGURED", "邮件服务未配置，请联系管理员"),
    REGISTRATION_DISABLED(403, "REGISTRATION_DISABLED", "注册功能已关闭，请联系管理员开通账号"),

    // User / RBAC
    USER_NOT_FOUND(404, "USER_NOT_FOUND", "用户不存在"),
    USER_ALREADY_EXISTS(409, "USER_ALREADY_EXISTS", "用户名或邮箱已被占用"),
    ROLE_NOT_FOUND(404, "ROLE_NOT_FOUND", "角色不存在"),
    ROLE_ALREADY_EXISTS(409, "ROLE_ALREADY_EXISTS", "角色编码已存在"),
    ROLE_BUILTIN_IMMUTABLE(400, "ROLE_BUILTIN_IMMUTABLE", "内置角色不可删除或改名"),
    PERMISSION_NOT_FOUND(404, "PERMISSION_NOT_FOUND", "权限不存在"),

    // OAuth client
    CLIENT_NOT_FOUND(404, "CLIENT_NOT_FOUND", "应用不存在"),
    CLIENT_ACCESS_DENIED(403, "CLIENT_ACCESS_DENIED", "无权访问该应用"),
    INVALID_REDIRECT_URI(400, "INVALID_REDIRECT_URI", "回调地址无效"),

    // API key
    API_KEY_NOT_FOUND(404, "API_KEY_NOT_FOUND", "API 密钥不存在"),

    // External account setup / binding
    EMAIL_TAKEN_MERGE_AVAILABLE(409, "EMAIL_TAKEN_MERGE_AVAILABLE", "\u8be5\u90ae\u7bb1\u5df2\u6709\u8d26\u53f7\uff0c\u53ef\u9009\u62e9\u5408\u5e76\u6216\u66f4\u6362\u90ae\u7bb1"),
    EXTERNAL_IDENTITY_ALREADY_BOUND(409, "EXTERNAL_IDENTITY_ALREADY_BOUND", "\u8be5\u7b2c\u4e09\u65b9\u8d26\u53f7\u5df2\u7ed1\u5b9a\u5176\u4ed6\u8d26\u6237"),
    EXTERNAL_SETUP_REQUIRED(403, "EXTERNAL_SETUP_REQUIRED", "\u8bf7\u5148\u5b8c\u6210\u8d26\u53f7\u8bbe\u7f6e"),

    // Files
    FILE_INVALID(400, "FILE_INVALID", "文件无效"),
    FILE_TOO_LARGE(400, "FILE_TOO_LARGE", "文件过大");

    private final int status;
    private final String code;
    private final String message;

    ErrorCode(int status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
