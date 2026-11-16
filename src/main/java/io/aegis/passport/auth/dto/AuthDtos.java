package io.aegis.passport.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

public final class AuthDtos {
    private AuthDtos() {}

    @Data
    public static class LoginRequest {
        @NotBlank private String username;
        @NotBlank private String password;
    }

    @Data
    public static class RegisterRequest {
        @NotBlank @Size(min = 3, max = 50) private String username;
        @NotBlank @Size(min = 6, max = 512) private String password;
        @Email private String email;
        private String phone;
        private String orgName;
        private Long organizationId;
        private Boolean enabled;
        private String verificationCode;
        // Admin-only
        private String role;
        private java.util.Set<String> groups;
        private String nickname;
    }

    @Data
    public static class LoginResponse {
        private String token;
        private Long userId;
        private String username;
        private String nickname;
        private String email;
        private String primaryRole;
    }

    @Data
    public static class SendCodeRequest {
        @Email @NotBlank private String email;
    }

    @Data
    public static class ChangePasswordRequest {
        @NotBlank private String oldPassword;
        @NotBlank @Size(min = 6) private String newPassword;
    }
}
