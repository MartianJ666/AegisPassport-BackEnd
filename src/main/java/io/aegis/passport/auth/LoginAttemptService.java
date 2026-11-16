package io.aegis.passport.auth;
import io.aegis.passport.config.PassportProperties;
import java.time.Clock;
import java.util.*;
import org.springframework.stereotype.Service;
/** Bounded, single-instance account lockout independent of external cache availability. */
@Service
public class LoginAttemptService {
 private final PassportProperties props; private final Clock clock;
 private final Map<String,Attempt> attempts=new HashMap<>();
 private record Attempt(int failures,long windowEnd,long lockEnd) {}
 @org.springframework.beans.factory.annotation.Autowired
 public LoginAttemptService(PassportProperties props){this(props,Clock.systemUTC());}
 LoginAttemptService(PassportProperties props,Clock clock){this.props=props;this.clock=clock;}
 private String key(String username){return Objects.toString(username,"").strip().toLowerCase(Locale.ROOT);}
 private Attempt current(String username){var a=attempts.get(key(username));if(a!=null&&Math.max(a.windowEnd,a.lockEnd)<=clock.millis()){attempts.remove(key(username));return null;}return a;}
 public synchronized boolean isLocked(String username){var a=current(username);return a!=null&&a.lockEnd>clock.millis();}
 public synchronized void loginFailed(String username){
  long now=clock.millis(),lockMs=props.getSecurity().getLogin().getLockSeconds()*1000L;
  attempts.entrySet().removeIf(e->Math.max(e.getValue().windowEnd,e.getValue().lockEnd)<=now);
  var a=current(username);int count=a==null?1:a.failures+1;
  if(a==null&&attempts.size()>=10000)throw io.aegis.passport.common.exception.BusinessException.of(io.aegis.passport.common.exception.ErrorCode.RATE_LIMITED);
  long end=a==null?now+Math.max(lockMs*2,300000):a.windowEnd;
  attempts.put(key(username),count>=props.getSecurity().getLogin().getMaxAttempts()?new Attempt(0,now+lockMs,now+lockMs):new Attempt(count,end,0));
 }
 public synchronized void loginSucceeded(String username){attempts.remove(key(username));}
 public synchronized long remainingLockSeconds(String username){var a=current(username);return a==null?0:Math.max(0,(a.lockEnd-clock.millis()+999)/1000);}
 public synchronized int remainingAttempts(String username){var a=current(username);return a!=null&&a.lockEnd>clock.millis()?0:Math.max(0,props.getSecurity().getLogin().getMaxAttempts()-(a==null?0:a.failures));}
}
