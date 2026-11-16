package io.aegis.passport.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import io.aegis.passport.config.PassportProperties;
import java.time.*;
class LoginThrottleTests {
 static class Time extends Clock {long now=1000;public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(now);}}
 @Test void countsLocksAndExpiresWithoutRedis(){var t=new Time();var s=new LoginAttemptService(new PassportProperties(),t);for(int i=0;i<5;i++)s.loginFailed(" TEST@example.test ");assertTrue(s.isLocked("test@example.test"));assertEquals(0,s.remainingAttempts("test@example.test"));assertEquals(300,s.remainingLockSeconds("test@example.test"));t.now+=300000;assertFalse(s.isLocked("test@example.test"));assertEquals(5,s.remainingAttempts("test@example.test"));}
 @Test void successResetsOnlyItsAccount(){var s=new LoginAttemptService(new PassportProperties());s.loginFailed("one");s.loginFailed("two");s.loginSucceeded("one");assertEquals(5,s.remainingAttempts("one"));assertEquals(4,s.remainingAttempts("two"));}
}
