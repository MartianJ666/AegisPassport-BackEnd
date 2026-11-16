package io.aegis.passport.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.data.redis.core.StringRedisTemplate;
class VerificationCodeTests {
 @Test void challengesAreNormalizedSingleUseAndRateLimited() {
  var service=new VerificationCodeService(mock(StringRedisTemplate.class));String code=service.generate("User@Example.invalid");
  assertThrows(io.aegis.passport.common.exception.BusinessException.class,()->service.generate("user@example.invalid"));
  assertTrue(service.verify("user@example.invalid",code));assertFalse(service.verify("USER@example.invalid",code));
 }
 @Test void fiveWrongAttemptsInvalidateChallenge() {
  var service=new VerificationCodeService(mock(StringRedisTemplate.class));String code=service.generate("limited@example.invalid");String wrong=code.equals("000000")?"111111":"000000";
  for(int i=0;i<5;i++)assertFalse(service.verify("limited@example.invalid",wrong));assertFalse(service.verify("limited@example.invalid",code));
 }
 @Test void concurrentVerificationConsumesOnlyOnce() throws Exception {
  var service=new VerificationCodeService(mock(StringRedisTemplate.class));String code=service.generate("concurrent@example.invalid");
  try(var pool=java.util.concurrent.Executors.newFixedThreadPool(4)) {
   var jobs=new java.util.ArrayList<java.util.concurrent.Future<Boolean>>();for(int i=0;i<16;i++)jobs.add(pool.submit(()->service.verify("concurrent@example.invalid",code)));
   int accepted=0;for(var job:jobs)if(job.get())accepted++;assertEquals(1,accepted);
  }
 }
}
