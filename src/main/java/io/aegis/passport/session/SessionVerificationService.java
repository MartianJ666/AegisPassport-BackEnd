package io.aegis.passport.session;

import io.aegis.passport.auth.VerificationCodeService;
import io.aegis.passport.email.EmailService;
import io.aegis.passport.user.entity.User;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SessionVerificationService {
    private static final String PREFIX = "session-vcode:";
    private final StringRedisTemplate redis;
    private final EmailService email;
    private final SecureRandom random = new SecureRandom();
    public void send(User user) {
        if (user.getEmail()==null || user.getEmail().isBlank()) throw new IllegalArgumentException("账户没有绑定邮箱");
        String code=String.format("%06d",random.nextInt(1_000_000));
        redis.opsForValue().set(PREFIX+user.getId(),code,10,TimeUnit.MINUTES);
        email.sendSessionVerificationCode(user.getEmail(), code);
    }
    public boolean verify(User user,String code) {
        String key=PREFIX+user.getId(); String stored=redis.opsForValue().get(key);
        if(stored!=null && stored.equals(code)){redis.delete(key);return true;} return false;
    }
}
