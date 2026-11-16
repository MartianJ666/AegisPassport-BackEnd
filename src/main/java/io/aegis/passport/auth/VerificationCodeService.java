package io.aegis.passport.auth;
import io.aegis.passport.common.exception.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

/** Single-use registration/profile email challenges; isolated from device challenges. */
@Service @RequiredArgsConstructor
public class VerificationCodeService {
 private final StringRedisTemplate redis;
 private final SecureRandom random=new SecureRandom();
 @Value("${passport.cache.provider:memory}") private String cacheProvider="memory";
 private final Map<String,Challenge> memory=new ConcurrentHashMap<>();
 private final Map<String,Instant> cooldown=new ConcurrentHashMap<>();
 private record Challenge(String code,Instant expires,int failures) {}
 private String email(String value) {
  if(value==null || value.length()>100 || !value.trim().matches("^[^\\s@]+@[^\\s@]+[.][^\\s@]+$"))throw BusinessException.of(ErrorCode.BAD_REQUEST,"邮箱格式无效");
  return value.trim().toLowerCase(Locale.ROOT);
 }
 public String generate(String address) {
  String email=email(address),code=String.format("%06d",random.nextInt(1_000_000));Instant now=Instant.now();
  if("redis".equals(cacheProvider)) {
   if(!Boolean.TRUE.equals(redis.opsForValue().setIfAbsent("registration-send:"+email,"1",60,TimeUnit.SECONDS)))throw BusinessException.of(ErrorCode.RATE_LIMITED,"请等待60秒后再发送验证码");
   redis.opsForValue().set("vcode:"+email,code,10,TimeUnit.MINUTES);redis.delete("vcode-attempts:"+email);
  } else {
   cooldown.entrySet().removeIf(x->!x.getValue().isAfter(now));memory.entrySet().removeIf(x->!x.getValue().expires().isAfter(now));
   var allowed=new AtomicBoolean();cooldown.compute(email,(k,until)->{if(until==null || !until.isAfter(now)){allowed.set(true);return now.plusSeconds(60);}return until;});
   if(!allowed.get())throw BusinessException.of(ErrorCode.RATE_LIMITED,"请等待60秒后再发送验证码");
   memory.put(email,new Challenge(code,now.plusSeconds(600),0));
  }
  return code;
 }
 public boolean verify(String address,String code) {
  String email=email(address);if(code==null || !code.matches("[0-9]{6}"))return false;
  if("redis".equals(cacheProvider)) {
   var script=new DefaultRedisScript<Long>("local v=redis.call('GET',KEYS[1]); if not v then return 0 end; local n=redis.call('INCR',KEYS[2]); if n==1 then redis.call('EXPIRE',KEYS[2],600) end; if n>5 then redis.call('DEL',KEYS[1]); return 0 end; if v==ARGV[1] then redis.call('DEL',KEYS[1],KEYS[2]); return 1 end; return 0",Long.class);
   return Long.valueOf(1).equals(redis.execute(script,List.of("vcode:"+email,"vcode-attempts:"+email),code));
  }
  var ok=new AtomicBoolean();memory.computeIfPresent(email,(k,value)->{
   if(!value.expires().isAfter(Instant.now()) || value.failures()>=5)return null;
   if(java.security.MessageDigest.isEqual(value.code().getBytes(java.nio.charset.StandardCharsets.US_ASCII),code.getBytes(java.nio.charset.StandardCharsets.US_ASCII))){ok.set(true);return null;}
   return value.failures()>=4?null:new Challenge(value.code(),value.expires(),value.failures()+1);
  });return ok.get();
 }
 public boolean hasActiveCode(String address) {
  String email=email(address);if("redis".equals(cacheProvider))return Boolean.TRUE.equals(redis.hasKey("vcode:"+email));
  var value=memory.get(email);return value!=null && value.expires().isAfter(Instant.now());
 }
}
