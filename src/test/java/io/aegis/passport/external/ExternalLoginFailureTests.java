package io.aegis.passport.external;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import io.aegis.passport.common.exception.*;
import io.aegis.passport.config.PassportProperties;
import org.springframework.mock.web.*;
class ExternalLoginFailureTests {
 @Test void parallelCallbacksKeepSeparateBrowserCredentialsAndSetupDestinations() throws Exception {
  var provider=mock(ExternalProviderAuthService.class);var props=new PassportProperties();props.setFrontendUrl("https://auth.example.com");
  var controller=new ExternalIdentityController(provider,null,null,props,mock(io.aegis.passport.audit.AuditLogService.class),null,null,null);
  String first="first-transaction-0000000001",second="second-transaction-000000002";
  when(provider.start("oidc")).thenReturn(new ExternalProviderAuthService.StartResult("https://identity.example.com/authorize", "first-browser",first), new ExternalProviderAuthService.StartResult("https://identity.example.com/authorize", "second-browser",second));
  var a=new MockHttpServletResponse();var b=new MockHttpServletResponse();controller.start("oidc",a);controller.start("oidc",b);
  var ca=a.getCookie("external_auth_"+first);var cb=b.getCookie("external_auth_"+second);assertNotNull(ca);assertNotNull(cb);assertNotEquals(ca.getName(),cb.getName());
  when(provider.parseOidcState(anyString())).thenCallRealMethod();
  for(int i=0;i<2;i++) {
   String tx=i==0?first:second,browser=i==0?"first-browser":"second-browser";
   var request=new MockHttpServletRequest();request.setParameter("state",tx+".original-state");request.setParameter("code","fixture-code");request.setCookies(ca,cb);var response=new MockHttpServletResponse();
   when(provider.complete(eq("oidc"),eq(tx),eq("original-state"),eq("fixture-code"),isNull(),eq(browser),same(request),same(response))).thenReturn(new ExternalProviderAuthService.CompleteResult(false,i==1));
   controller.callback("oidc",request,response);
   assertEquals("https://auth.example.com"+(i==0?"/auth/login?external=complete":"/auth/complete-external?external=complete"),response.getRedirectedUrl());
  }
 }
 @Test void closedRegistrationCallbackShowsBindingGuidanceWithoutRawError() throws Exception {
  var provider=mock(ExternalProviderAuthService.class);var props=new PassportProperties();props.setFrontendUrl("https://auth.example.com");
  var controller=new ExternalIdentityController(provider,mock(ExternalAccountService.class),mock(ThirdPartyLoginConfigService.class),props,mock(io.aegis.passport.audit.AuditLogService.class),mock(io.aegis.passport.user.UserRepository.class),mock(io.aegis.passport.security.RsaTransportService.class),mock(org.springframework.security.crypto.password.PasswordEncoder.class));
  var req=new MockHttpServletRequest();req.setParameter("tx","fixture");req.setParameter("state","secret-state");req.setParameter("code","secret-code");req.setCookies(new jakarta.servlet.http.Cookie("external_auth","fixture-browser"));var response=new MockHttpServletResponse();
  when(provider.complete(eq("oidc"),anyString(),anyString(),anyString(),isNull(),anyString(),same(req),same(response))).thenThrow(BusinessException.of(ErrorCode.REGISTRATION_DISABLED));
  controller.callback("oidc",req,response);
  assertEquals("https://auth.example.com/auth/external-error?reason=account_not_linked&provider=oidc",response.getRedirectedUrl());
  assertFalse(response.getRedirectedUrl().contains("secret"));
 }
 @Test void cancellationAndUnknownErrorsHaveSafeDistinctCategories(){
  assertTrue(ExternalLoginFailure.target("https://auth.example.com","oidc",new Exception("sensitive remote error"),true).contains("reason=cancelled"));
  String target=ExternalLoginFailure.target("https://auth.example.com/","untrusted&redirect=https://attacker.invalid",new Exception("sensitive remote error"),false);
  assertEquals("https://auth.example.com/auth/external-error?reason=service_error&provider=other",target);
 }
 @Test void disabledAndInvalidFlowRemainDistinctFromUnboundIdentity(){
  assertTrue(ExternalLoginFailure.target("https://auth.example.com","oidc",BusinessException.of(ErrorCode.ACCOUNT_DISABLED),false).contains("reason=account_disabled"));
  assertTrue(ExternalLoginFailure.target("https://auth.example.com","oidc",BusinessException.of(ErrorCode.BAD_REQUEST),false).contains("reason=verification_failed"));
 }
}
