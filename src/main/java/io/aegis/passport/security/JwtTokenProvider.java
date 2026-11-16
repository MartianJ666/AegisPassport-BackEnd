package io.aegis.passport.security;

import io.aegis.passport.config.PassportProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Issues and validates our own stateless JWT access tokens (used for the
 * dashboard / REST API — separate from the OAuth2 access tokens issued by
 * Spring Authorization Server).
 */
@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtTokenProvider(PassportProperties props) {
        String configured = props.getJwt().getSecret();
        byte[] keyBytes;
        if (configured == null || configured.isBlank()) {
            keyBytes = new byte[32]; new java.security.SecureRandom().nextBytes(keyBytes);
            log.warn("JWT_SECRET is unset: using an ephemeral signing key for this process");
        } else {
            keyBytes = configured.getBytes(StandardCharsets.UTF_8);
        }
        // Ensure minimum 256 bits for HS256.
        if (keyBytes.length < 32) {
            throw new IllegalStateException("passport.jwt.secret 至少需要 32 个字符");
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = props.getJwt().getExpirationMs();
    }

    public String generate(Long userId, String username) {
        return generate(userId, username, null);
    }

    public String generate(Long userId, String username, String sessionId) {
        Date now = new Date();
        return Jwts.builder()
                .subject(username)
                .claim("uid", userId)
                .claim("sid", sessionId)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    public boolean validate(String token) {
        try {
            Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.debug("[JWT] 验证失败: {}", e.getMessage());
            return false;
        }
    }

    public String extractUsername(String token) {
        return claims(token).getSubject();
    }

    public Long extractUserId(String token) {
        return claims(token).get("uid", Long.class);
    }

    public String extractSessionId(String token) { return claims(token).get("sid", String.class); }

    private Claims claims(String token) {
        return Jwts.parser().verifyWith(signingKey).build()
                .parseSignedClaims(token).getPayload();
    }
}
