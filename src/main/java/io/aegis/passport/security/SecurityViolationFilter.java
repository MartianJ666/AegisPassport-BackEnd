package io.aegis.passport.security;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor; import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
@Slf4j @Component @RequiredArgsConstructor
public class SecurityViolationFilter extends OncePerRequestFilter {
    private final UserRepository userRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && path.startsWith("/api/") && !path.startsWith("/api/auth/") && !path.startsWith("/api/config/") && !path.startsWith("/api/rsa/") && !path.startsWith("/api/public/")) {
            Optional<User> userOpt = Optional.empty();
            if (auth.getPrincipal() instanceof PassportUserPrincipal pp) userOpt = userRepository.findById(pp.getId());
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                if (user.isBanned()) {
                    log.warn("[安全] 被封禁用户 {} 尝试访问 {}", user.getUsername(), path);
                    response.setStatus(403);
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().write("{\"code\":403,\"errorCode\":\"ACCOUNT_BANNED\",\"message\":\"账户已被封禁\"}");
                    return;
                }
            }
        }
        chain.doFilter(request, response);
    }
}
