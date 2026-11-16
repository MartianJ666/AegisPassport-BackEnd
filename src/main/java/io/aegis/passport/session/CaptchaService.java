package io.aegis.passport.session;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CaptchaService {
    private final StringRedisTemplate redis;
    private final SecureRandom random = new SecureRandom();
    public Challenge issue(String userId, String action) {
        int a=random.nextInt(8)+2, b=random.nextInt(8)+2; String id=UUID.randomUUID().toString();
        redis.opsForValue().set(key(id), userId+"|"+action+"|"+(a+b), Duration.ofMinutes(2));
        return new Challenge(id, a+" + "+b+" = ?", 120);
    }
    public boolean verifyAndConsume(String id, String answer, String userId, String action) {
        String value=redis.opsForValue().get(key(id));
        if(value==null || answer==null || !value.startsWith(userId+"|"+action+"|")) return false;
        String expected=value.substring(value.lastIndexOf('|')+1);
        if(!expected.equals(answer.trim())) return false;
        return Boolean.TRUE.equals(redis.delete(key(id)));
    }
    private String key(String id){return "captcha:session:"+id;}
    public record Challenge(String challengeId,String question,int expiresIn){}
}
