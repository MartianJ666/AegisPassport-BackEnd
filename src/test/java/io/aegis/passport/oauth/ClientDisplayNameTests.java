package io.aegis.passport.oauth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import io.aegis.passport.client.*;
import io.aegis.passport.client.entity.OAuthClient;
import java.util.*;
class ClientDisplayNameTests {
 final ConsentTokenService consents=new ConsentTokenService();
 final AccountConfirmTokenService confirms=new AccountConfirmTokenService();
 final OAuthClientRepository clients=mock(OAuthClientRepository.class);
 final ConsentRedirectController controller=new ConsentRedirectController(consents,confirms,new TempAuthTokenService(),new io.aegis.passport.config.PassportProperties(),mock(OAuthClientAccountRepository.class),mock(io.aegis.passport.user.UserRepository.class),mock(io.aegis.passport.security.PassportUserDetailsService.class),clients,mock(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService.class));
 @Test void bothOpaqueLookupsReturnCurrentNameAndRetainProtocolIdentifier(){
  var client=OAuthClient.builder().clientId("fixture-id").clientName("DEOIDC").clientSecret("must-not-leak").build();when(clients.findByClientId("fixture-id")).thenReturn(Optional.of(client));
  String confirm=confirms.create("fixture-id","","https://example.invalid/authorize");
  var first=controller.accountConfirmInfo(confirm,null).getBody().getData();assertEquals("DEOIDC",first.get("clientName"));assertEquals("fixture-id",first.get("clientId"));assertFalse(first.containsKey("clientSecret"));
  client.setClientName("更新后的名称");
  String consent=consents.create("fixture-id",List.of("openid"),"state",null);
  assertEquals("更新后的名称",controller.info(consent).getBody().getData().get("clientName"));
  assertEquals("更新后的名称",controller.accountConfirmInfo(confirm,null).getBody().getData().get("clientName"));
 }
 @Test void invalidTokensDoNotAllowAnonymousClientEnumeration(){
  assertThrows(io.aegis.passport.common.exception.BusinessException.class,()->controller.accountConfirmInfo("invalid",null));
  assertThrows(io.aegis.passport.common.exception.BusinessException.class,()->controller.info("invalid"));verifyNoInteractions(clients);
 }
 @Test void missingClientFallsBackToGenericLabel(){
  when(clients.findByClientId("gone")).thenReturn(Optional.empty());
  var token=confirms.create("gone","","https://example.invalid/authorize");
  assertEquals("此应用",controller.accountConfirmInfo(token,null).getBody().getData().get("clientName"));
 }
}
