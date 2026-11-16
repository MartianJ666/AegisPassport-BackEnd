package io.aegis.passport.external;
import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.util.RequestTrace;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/** Public, fixed error categories only; never put provider errors or credentials in URLs. */
public final class ExternalLoginFailure {
 private ExternalLoginFailure() {}
 public static String target(String frontend,String provider,Exception error,boolean cancelled) {
  String reason="service_error";
  if(cancelled)reason="cancelled";
  else if(error instanceof BusinessException business)reason=switch(business.getErrorCode()) {
   case REGISTRATION_DISABLED -> "account_not_linked";
   case ACCOUNT_DISABLED -> "account_disabled";
   case ACCOUNT_LOCKED -> "account_locked";
   case CONFLICT,EXTERNAL_IDENTITY_ALREADY_BOUND -> "account_conflict";
   case BAD_REQUEST,UNAUTHORIZED -> "verification_failed";
   default -> "service_error";
  };
  String known=Set.of("oidc").contains(provider==null?"":provider)?provider:"other";
  String trace=RequestTrace.current();
  return frontend.replaceAll("/+$","")+"/auth/external-error?reason="+reason+"&provider="+known
   +(trace.matches("[a-fA-F0-9]{16,32}")?"&traceId="+URLEncoder.encode(trace,StandardCharsets.UTF_8):"");
 }
}
