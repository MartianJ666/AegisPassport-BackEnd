package io.aegis.passport.security;
import io.aegis.passport.PassportApplication;
import io.aegis.passport.user.*;import io.aegis.passport.user.entity.User;
import io.aegis.passport.client.*;import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.session.*;import io.aegis.passport.oauth.*;
import java.net.*;import java.net.http.*;import java.time.*;import java.util.*;import java.util.regex.*;
import org.springframework.boot.SpringApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.fasterxml.jackson.databind.*;
import org.springframework.security.oauth2.server.authorization.*;
@org.springframework.boot.test.context.SpringBootTest(webEnvironment=org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT)
@org.springframework.test.context.ActiveProfiles("local")
@org.springframework.test.context.TestPropertySource(properties={"spring.datasource.url=jdbc:h2:mem:oauth-flow-regression;MODE=MySQL;DB_CLOSE_DELAY=-1", "spring.jpa.hibernate.ddl-auto=create-drop", "passport.jwt.secret=oauth-flow-test-only-secret-at-least-32-characters", "passport.bootstrap-admin.password=oauth-flow-test-only-password"})
public class OAuthFlowRegressionTests {
 @org.springframework.beans.factory.annotation.Autowired org.springframework.context.ConfigurableApplicationContext ctx;
 @org.springframework.boot.test.web.server.LocalServerPort int port;
 @org.junit.jupiter.api.BeforeEach void localOrigin(){base="http://127.0.0.1:"+port;}
 static String base;
 static final HttpClient http=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
 static final ObjectMapper json=new ObjectMapper();static int serial;
 static void check(boolean ok,String label){if(!ok)throw new AssertionError(label);System.out.println("PASS "+label);}
 static String enc(String s){return URLEncoder.encode(s,java.nio.charset.StandardCharsets.UTF_8);}
 static HttpResponse<String> get(String url,String jwt)throws Exception{return http.send(HttpRequest.newBuilder(URI.create(url)).header("Accept",url.contains("/api/")?"application/json":"text/html").header("Cookie",jwt==null?"":"__Host-passport-token="+jwt).GET().build(),HttpResponse.BodyHandlers.ofString());}
 static String location(HttpResponse<String> r){String s=r.headers().firstValue("Location").orElseThrow(()->new AssertionError("Expected redirect: "+r.statusCode()+" "+r.body()));return s.startsWith("/")?base+s:s;}
 static String url(String id){return base+"/oauth2/authorize?response_type=code&client_id="+id+"&redirect_uri="+enc("https://callback.example.invalid/cb")+"&scope=openid%20profile&state=app-state-"+(++serial)+"&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&code_challenge_method=S256&aegis_account_confirmed=1";}
 record Flow(String client,String token,JsonNode data){}
 static Flow flow(String id,String jwt,String temp)throws Exception{
  String start=url(id)+(temp==null?"":"&aegis_temp_token="+temp);
  var redirect=get(location(get(start,jwt)),jwt);
  String consent=location(redirect);check(consent.contains("token="),"pending SAS identity reaches consent");
  String token=consent.substring(consent.indexOf("token=")+6);
  var info=get(base+"/api/consent/info?token="+token,null);check(info.statusCode()==200,"opaque consent lookup "+info.statusCode()+" "+(info.statusCode()==200?"":info.body()));
  return new Flow(id,token,json.readTree(info.body()).path("data"));
 }
 static HttpResponse<String> post(Flow f,String state,boolean approve,String jwt)throws Exception{
  String body="client_id="+f.client+"&token="+enc(f.token)+"&state="+enc(state)+(approve?"&scope=openid&scope=profile":"");
  return http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/authorize")).header("Content-Type","application/x-www-form-urlencoded").header("Origin","http://localhost:8420").header("Cookie",jwt==null?"":"__Host-passport-token="+jwt).POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
 }
 static String jwt(org.springframework.context.ConfigurableApplicationContext ctx,User u){
  var session=AuthSession.builder().id(UUID.randomUUID().toString()).user(u).deviceHash("fixture-device").deviceLabel("Fixture browser").authMethod("TEST").createdAt(Instant.now()).lastSeenAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
  ctx.getBean(AuthSessionRepository.class).saveAndFlush(session);return ctx.getBean(JwtTokenProvider.class).generate(u.getId(),u.getUsername(),session.getId());
 }
 static void codeOwner(org.springframework.context.ConfigurableApplicationContext ctx,HttpResponse<String> result,String owner){
  check(result.statusCode()==200&&result.body().contains("oauth-continue.js"),"callback navigation document: status="+result.statusCode()+" body="+result.body());
  var matcher=Pattern.compile("code=([^&\" ]+)").matcher(result.body());check(matcher.find(),"authorization code returned");
  var saved=ctx.getBean(OAuth2AuthorizationService.class).findByToken(URLDecoder.decode(matcher.group(1),java.nio.charset.StandardCharsets.UTF_8),new OAuth2TokenType("code"));
  check(saved!=null&&owner.equals(saved.getPrincipalName()),"code belongs to explicitly selected account");
 }
 @org.junit.jupiter.api.Test void authorizationFlowsRetainIdentityStateAndContinuation() throws Exception {
   var script=get(base+"/oauth-continue.js",null);
   check(script.statusCode()==200 && script.body().contains("window.location.replace(link.href)"), "anonymous browser can load callback navigation script");
   var users=ctx.getBean(UserRepository.class);var clients=ctx.getBean(OAuthClientRepository.class);var temps=ctx.getBean(TempAuthTokenService.class);
   User a=users.saveAndFlush(User.builder().username("audit-main-a").password("unused").build());
   User b=users.saveAndFlush(User.builder().username("audit-switched-b").password("unused").build());
   String jwtA=jwt(ctx,a);

   for(String id:List.of("audit-normal","audit-switch","audit-other","audit-revoke","audit-no-main","audit-deny","audit-parallel"))clients.saveAndFlush(OAuthClient.builder().clientId(id).clientName(id).clientSecret(ctx.getBean(PasswordEncoder.class).encode("fixture-secret")).redirectUris("https://callback.example.invalid/cb").build());
   var anonymous=get(url("audit-normal"),null);
   check(anonymous.statusCode()==302 && location(anonymous).contains("redirect="), "anonymous login retains OAuth continuation");
   var normal=flow("audit-normal",jwtA,null);
   check(normal.data.path("accountConfirmToken").asText().length()>40,"consent screen offers correct confirmation token type");
   var swappedInfo=get(base+"/api/account-confirm/info?token="+normal.data.path("accountConfirmToken").asText()+"&tempToken="+temps.create("audit-normal",b.getUsername()),null);
   var swapped=json.readTree(swappedInfo.body()).path("data");check(swappedInfo.statusCode()==200&&swapped.path("currentUser").path("username").asText().equals(b.getUsername()),"consent-screen switch renders selected account");
   check(swapped.path("authorizeUrl").asText().contains("code_challenge=")&&swapped.path("authorizeUrl").asText().contains("state=app-state-"),"switch retains original PKCE and client state");
   check(post(normal,"wrong-state",true,jwtA).statusCode()==400,"mismatched consent state rejected");
   codeOwner(ctx,post(normal,normal.data.path("state").asText(),true,null),a.getUsername());
   check(post(normal,normal.data.path("state").asText(),true,jwtA).statusCode()==400,"used consent cannot replay");
   var silent=get(url("audit-normal"),jwtA);check(silent.statusCode()==302&&location(silent).contains("code="),"previously approved login returns directly to client");
   var denied=flow("audit-deny",jwtA,null);var denial=post(denied,denied.data.path("state").asText(),false,null);check(denial.body().contains("error=access_denied")&&denial.body().contains("state=app-state-"),"refusal returns original client state");
   var restricted=clients.findByClientId("audit-switch").orElseThrow();restricted.setDeniedUsers(a.getId().toString());clients.saveAndFlush(restricted);
   var switched=flow("audit-switch",jwtA,temps.create("audit-switch",b.getUsername()));
   check(switched.data.path("currentUser").path("username").asText().equals(b.getUsername()),"main-account ACL and cookie cannot replace switched identity");
   codeOwner(ctx,post(switched,switched.data.path("state").asText(),true,jwtA),b.getUsername());
   var profile=get(base+"/api/user/profile",jwtA);check(json.readTree(profile.body()).path("data").path("username").asText().equals(a.getUsername()),"temporary switch leaves main account unchanged");
   var noMain=flow("audit-no-main",null,temps.create("audit-no-main",b.getUsername()));codeOwner(ctx,post(noMain,noMain.data.path("state").asText(),true,null),b.getUsername());
   String temp=temps.create("audit-other",b.getUsername());check(location(get(url("audit-normal")+"&aegis_temp_token="+temp,jwtA)).contains("invalid=1"),"wrong-client switch fails instead of falling back");
   check(location(get(url("audit-normal")+"&aegis_temp_token=expired-fixture",jwtA)).contains("invalid=1"),"expired switch fails instead of using main account");
   var mismatch=get(base+"/api/account-confirm/info?token="+normal.data.path("accountConfirmToken").asText()+"&tempToken="+temps.create("audit-other",b.getUsername()),null);check(mismatch.statusCode()==401,"confirmation rejects another client's switch token");
   String confirmation=ctx.getBean(AccountConfirmTokenService.class).create("audit-normal",a.getUsername(),url("audit-normal"));
   check(location(get(url("audit-normal")+"&aegis_confirm_token="+confirmation,jwt(ctx,b))).contains("invalid=1"),"account changed in another tab cannot silently confirm different identity");
   var revoke=flow("audit-revoke",jwtA,null);var rc=clients.findByClientId("audit-revoke").orElseThrow();rc.setEnabled(false);clients.saveAndFlush(rc);check(post(revoke,revoke.data.path("state").asText(),true,jwtA).statusCode()==403,"application revoked after page load cannot authorize");
   var parallelA=flow("audit-parallel",jwtA,null);var parallelB=flow("audit-parallel",jwtA,temps.create("audit-parallel",b.getUsername()));
   codeOwner(ctx,post(parallelA,parallelA.data.path("state").asText(),true,jwtA),a.getUsername());codeOwner(ctx,post(parallelB,parallelB.data.path("state").asText(),true,jwtA),b.getUsername());

 }
}
