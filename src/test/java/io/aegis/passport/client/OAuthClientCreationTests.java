package io.aegis.passport.client;

import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.WebApplicationContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("local")
@TestPropertySource(properties = {
 "spring.datasource.url=jdbc:h2:mem:oauth-creation-regression;MODE=MySQL;DB_CLOSE_DELAY=-1",
 "spring.flyway.enabled=false", "spring.jpa.hibernate.ddl-auto=create-drop",
 "passport.bootstrap-admin.password=local-regression-only-password",
 "passport.jwt.secret=local-regression-only-secret-at-least-32bytes",
 "passport.upload.dir=build/test-uploads",
 "passport.oidc.key-dir=build/test-keys"
})
class OAuthClientCreationTests {
 @Autowired OAuthClientService service;
 @Autowired OAuthClientRepository clients;
 @Autowired UserRepository users;
 @Autowired PasswordEncoder encoder;
 @Autowired PlatformTransactionManager transactions;
 @Autowired WebApplicationContext web;

 @Test void creationKeepsHashAfterTransactionCommitAndAuthenticatesSecret() throws Exception {
  users.save(User.builder().username("oauth-regression-owner").password(encoder.encode("test-only")).build());
  var tx = new TransactionTemplate(transactions);
  OAuthClient created = tx.execute(status -> {
   try {
    return service.create(new OAuthClientService.ClientRequest("Regression OAuth", "test-only",
      "https://example.invalid/callback", "authorization_code,refresh_token", "openid,profile,email",
      900, 604800, 300, true, true, null, null, null), null, "oauth-regression-owner", true);
   } catch (Exception e) { throw new RuntimeException(e); }
  });
  assertNotNull(created);
  OAuthClient stored = clients.findByClientId(created.getClientId()).orElseThrow();
  assertNotEquals(created.getClientSecret(), stored.getClientSecret(), "raw secret must never replace persistent hash");
  assertTrue(encoder.matches(created.getClientSecret(), stored.getClientSecret()));
  var mvc = org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(post("/oauth2/token").with(httpBasic(created.getClientId(), created.getClientSecret()))
    .param("grant_type", "authorization_code").param("code", "nonexistent")
    .param("redirect_uri", "https://example.invalid/callback"))
    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
  mvc.perform(post("/oauth2/token").param("client_id", created.getClientId()).param("client_secret", created.getClientSecret())
    .param("grant_type", "authorization_code").param("code", "nonexistent")
    .param("redirect_uri", "https://example.invalid/callback"))
    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
  mvc.perform(post("/oauth2/token").with(httpBasic(created.getClientId(), "incorrect-secret"))
    .param("grant_type", "authorization_code").param("code", "nonexistent"))
    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
 }

 @Test void updatePersistsAllEditableOAuthFields() throws Exception {
  var seed=clients.save(OAuthClient.builder().clientId("audit-update-fields").clientName("Audit test")
   .clientSecret(encoder.encode("test-only")).redirectUris("https://example.invalid/callback").build());
  var request=new OAuthClientService.ClientRequest("Audit test", "", "https://example.invalid/callback",
   "authorization_code,refresh_token,client_credentials", "openid,profile,email", 600, 3600, 60,
   false, true, null, null, null);
  service.update(seed.getClientId(),request,null,"audit-test",true);
  var actual=clients.findByClientId(seed.getClientId()).orElseThrow();
  assertAll("all UI-editable OAuth fields must persist",
   ()->assertFalse(actual.isRequirePkce(),"requirePkce update is ignored"),
   ()->assertEquals(request.grantTypes(),actual.getGrantTypes(),"grantTypes update is ignored"),
   ()->assertEquals(60,actual.getAuthorizationCodeTtl(),"authorizationCodeTtl update is ignored"));
 }
 @Test void clientRequestSupportsEnabledSwitch() {
  assertTrue(java.util.Arrays.stream(OAuthClientService.ClientRequest.class.getRecordComponents())
   .anyMatch(c->c.getName().equals("enabled")),"UI enabled switch has no backend request field");
 }
 @Test void invalidTokenLifetimeIsRejectedBeforeCreatingClient() {
  users.save(User.builder().username("audit-invalid-ttl").password(encoder.encode("test-only")).build());
  var request=new OAuthClientService.ClientRequest("Invalid TTL", "", "https://example.invalid/callback",
   "authorization_code,refresh_token","openid",-1,604800,300,true,true,null,null,null);
  assertThrows(RuntimeException.class,()->service.create(request,null,"audit-invalid-ttl",true),
   "negative token lifetime must not be persisted as a usable client");
 }

 @Autowired io.aegis.passport.session.SessionService auditSessions;
 @Autowired io.aegis.passport.security.JwtTokenProvider auditTokens;
 @Autowired io.aegis.passport.user.UserService auditUsers;
 @Test void revokedDeviceMustNotKeepDashboardAccess() throws Exception {
  var u=users.save(User.builder().username("audit-revocation").password(encoder.encode("test-only")).build());
  var request=new org.springframework.mock.web.MockHttpServletRequest();
  request.addHeader("X-Device-ID","audit_device_12345678901234567890");
  var session=auditSessions.create(u,request,"PASSWORD");
  var token=auditTokens.generate(u.getId(),u.getUsername(),session.getId());
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile")
   .header("Authorization","Bearer "+token)).andExpect(status().isOk());
  assertEquals(1,auditSessions.revokeOwned(u.getId(),java.util.List.of(session.getId()),"audit-test","TEST_ONLY"));
  assertFalse(auditSessions.active(session.getId(),u.getId()));
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile")
   .header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
 }
 @Test void clearingOptionalProfileFieldsMustPersist() {
  var u=users.save(User.builder().username("audit-clear-profile").password(encoder.encode("test-only"))
   .nickname("Old nickname").phone("123456789").orgName("Old organization").build());
  var req=new io.aegis.passport.user.dto.UserDtos.UpdateProfileRequest();
  req.setNickname("");req.setPhone("");
  auditUsers.updateProfile(u.getUsername(),req);
  var actual=users.findById(u.getId()).orElseThrow();
  assertAll("cleared optional profile fields must persist",
   ()->assertTrue(actual.getNickname()==null||actual.getNickname().isEmpty(),"nickname remains unchanged"),
   ()->assertTrue(actual.getPhone()==null||actual.getPhone().isEmpty(),"phone remains unchanged"),
   ()->assertEquals("Old organization",actual.getOrgName(),"self profile must not change administrator-assigned organization"));
 }

 @Autowired io.aegis.passport.audit.AuditLogService auditLogService;
 @Autowired io.aegis.passport.session.AuthSessionRepository auditSessionRepo;
 @Test void auditLogFiltersMustNotThrow() {
  var page=org.springframework.data.domain.PageRequest.of(0,10);
  assertAll("audit filter combinations must work",
   ()->assertDoesNotThrow(()->auditLogService.search(null,null,"no-such-user",null,null,null,page)),
   ()->assertDoesNotThrow(()->auditLogService.search("auth",null,null,null,null,null,page)),
   ()->assertDoesNotThrow(()->auditLogService.search(null,"LOGIN",null,null,null,null,page)),
   ()->assertDoesNotThrow(()->auditLogService.search(null,null,null,null,null,false,page)));
 }
 @Test void offlineSessionDeletionMustActuallyRemoveListedOfflineRecord() {
  var u=users.save(User.builder().username("audit-offline-delete").password(encoder.encode("test-only")).build());
  var session=auditSessions.create(u,new org.springframework.mock.web.MockHttpServletRequest(),"PASSWORD");
  session=auditSessionRepo.findById(session.getId()).orElseThrow();
  session.setLastSeenAt(java.time.Instant.now().minusSeconds(600));auditSessionRepo.save(session);
  var view=auditSessions.list(u.getId(),null).getFirst();assertFalse(view.online());
  assertEquals(1,auditSessions.deleteOwnedOffline(u.getId(),java.util.List.of(session.getId())));
  assertFalse(auditSessionRepo.existsById(session.getId()),"offline row was counted as deleted but remains stored");
 }

 @Autowired io.aegis.passport.oauth.OidcUserInfoMapper auditOidc;
 @Test void changedUnverifiedEmailMustNotBeAssertedVerifiedByOidc() {
  var u=users.save(User.builder().username("audit-email-verification").password(encoder.encode("test-only"))
    .email("original@example.invalid").build());
  var req=new io.aegis.passport.user.dto.UserDtos.UpdateProfileRequest();
  req.setEmail("unverified-new@example.invalid");
  auditUsers.updateProfile(u.getUsername(),req);
  var info=auditOidc.map(u.getUsername(),java.util.Set.of("openid","email"));
  assertEquals(req.getEmail(),info.getEmail());
  assertFalse(Boolean.TRUE.equals(info.getEmailVerified()),"profile-edited email has never been verified but OIDC asserts email_verified=true");
 }

 @Autowired io.aegis.passport.apikey.ApiKeyService auditKeys;
 @Test void apiKeyLifecycleAndOwnerIsolationWork() {
  users.save(User.builder().username("audit-key-owner").password(encoder.encode("test-only")).build());
  users.save(User.builder().username("audit-key-other").password(encoder.encode("test-only")).build());
  var created=auditKeys.create("audit-key-owner","Test key","verify",java.time.Instant.now().plusSeconds(3600));
  var id=((Number)created.get("id")).longValue();
  var key=(String)created.get("apiKey");var secret=(String)created.get("apiSecret");
  assertEquals(true,auditKeys.verify(key,secret).get("valid"));
  assertEquals(false,auditKeys.verify(key,"incorrect-secret").get("valid"));
  assertThrows(RuntimeException.class,()->auditKeys.deleteMine(id,"audit-key-other"));
  auditKeys.toggleMine(id,"audit-key-owner");assertEquals(false,auditKeys.verify(key,secret).get("valid"));
  var expired=auditKeys.create("audit-key-owner","Expired test key","verify",java.time.Instant.now().minusSeconds(10));
  assertEquals(false,auditKeys.verify((String)expired.get("apiKey"),(String)expired.get("apiSecret")).get("valid"));
 }
 @Test void anonymousAndUnprivilegedAccountsCannotReadAdminUsers() throws Exception {
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile"))
   .andExpect(status().isUnauthorized());
  var u=users.save(User.builder().username("audit-basic-user").password(encoder.encode("test-only")).build());
  var token=trackedToken(u);
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/admin/users")
   .header("Authorization","Bearer "+token)).andExpect(status().isForbidden());
 }

 @Test void apiKeyListsAndTogglesUseSafeDetachedResponses() throws Exception {
  var owner=uploadUser("key-response-owner");var jwt=trackedToken(owner);
  var created=auditKeys.create(owner.getUsername(),"API-key response regression","read",null);
  var id=((Number)created.get("id")).longValue();
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  for(String path:java.util.List.of("/api/admin/api-keys","/api/api-keys/my")) {
   var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(path).header("Authorization","Bearer "+jwt))
    .andExpect(status().isOk()).andExpect(jsonPath("$.data[*].ownerName",org.hamcrest.Matchers.hasItem(owner.getUsername())))
    .andReturn().getResponse().getContentAsString();
   assertFalse(response.contains("apiSecret"));assertFalse(response.contains("password"));assertFalse(response.contains("hibernateLazyInitializer"));
  }
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/admin/api-keys/"+id+"/toggle").header("Authorization","Bearer "+jwt))
   .andExpect(status().isOk()).andExpect(jsonPath("$.data.enabled").value(true)).andExpect(jsonPath("$.data.adminDisabled").value(true))
   .andExpect(jsonPath("$.data.apiSecret").doesNotExist()).andExpect(jsonPath("$.data.owner").doesNotExist());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/api-keys/my/"+id+"/toggle").header("Authorization","Bearer "+jwt))
   .andExpect(status().isOk()).andExpect(jsonPath("$.data.enabled").value(false)).andExpect(jsonPath("$.data.adminDisabled").value(true))
   .andExpect(jsonPath("$.data.ownerName").value(owner.getUsername())).andExpect(jsonPath("$.data.apiSecret").doesNotExist());
 }
 @Test void apiKeyAdministrationAndOwnershipRemainEnforced() throws Exception {
  var admin=uploadUser("key-access-admin");var basic=users.save(User.builder().username("key-access-basic").password(encoder.encode("test-only")).primaryRole("member").roles(new java.util.HashSet<>(java.util.Set.of(testRoles.findByCode("member").orElseThrow()))).build());
  var created=auditKeys.create(admin.getUsername(),"Protected API-key response","read",null);var id=((Number)created.get("id")).longValue();
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/admin/api-keys")).andExpect(status().isUnauthorized());
  var jwt=trackedToken(basic);
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/admin/api-keys").header("Authorization","Bearer "+jwt)).andExpect(status().isForbidden());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/admin/api-keys/"+id+"/toggle").header("Authorization","Bearer "+jwt)).andExpect(status().isForbidden());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/api-keys/my/"+id+"/toggle").header("Authorization","Bearer "+jwt)).andExpect(status().isNotFound());
  assertEquals(true,auditKeys.verify((String)created.get("apiKey"),(String)created.get("apiSecret")).get("valid"));
 }

 private String trackedToken(User user) {
  var session=auditSessions.create(user,new org.springframework.mock.web.MockHttpServletRequest(),"TEST");
  return auditTokens.generate(user.getId(),user.getUsername(),session.getId());
 }
 @Autowired io.aegis.passport.rbac.RoleRepository testRoles;
 @Autowired io.aegis.passport.file.FileStorageService uploadStorage;
 private User uploadUser(String name) {
  return users.save(User.builder().username(name).password(encoder.encode("test-only"))
   .roles(java.util.Set.of(testRoles.findByCode("admin").orElseThrow())).primaryRole("admin").build());
 }
 private byte[] image(String format) throws Exception {
  if (format.equals("webp")) return java.util.Base64.getDecoder().decode("UklGRjYAAABXRUJQVlA4ICoAAACQAQCdASoCAAIAAUAmJaACdLoAA5gA/vLrf/ziX8kfoF3Z/9x2Buu8QAA=");
  var out=new java.io.ByteArrayOutputStream();
  assertTrue(javax.imageio.ImageIO.write(new java.awt.image.BufferedImage(2,2,java.awt.image.BufferedImage.TYPE_INT_RGB),format,out));
  return out.toByteArray();
 }
 @Test void avatarAcceptsRealPngJpegGifAndStoresRetrievableFile() throws Exception {
  var u=uploadUser("upload-avatar-regression");var token=trackedToken(u);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  for(String format:java.util.List.of("png","jpeg","gif","webp")) {
   var bytes=image(format);
   mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart("/api/files/avatar")
    .file(new org.springframework.mock.web.MockMultipartFile("file","avatar."+format,"image/"+format,bytes))
    .header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.data.url").isString());
   var avatar=users.findById(u.getId()).orElseThrow().getAvatar();
   mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(avatar))
    .andExpect(status().isOk()).andExpect(content().bytes(bytes));
  }
 }
 @Test void oauthCreateAndEditAcceptPngIconAndPersistEnabled() throws Exception {
  var u=uploadUser("upload-client-regression"); var token=trackedToken(u);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  var data=new org.springframework.mock.web.MockMultipartFile("data","data.json","application/json",
   "{\"clientName\":\"Upload regression\",\"redirectUris\":\"https://example.invalid/callback\",\"enabled\":false}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
  var png=new org.springframework.mock.web.MockMultipartFile("icon","icon.png","image/png",image("png"));
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart("/api/clients").file(data).file(png)
   .header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.data.enabled").value(false));
  var c=clients.findByOwnerId(u.getId()).getFirst();assertFalse(c.isEnabled());assertNotNull(c.getClientIcon());
  var update=new org.springframework.mock.web.MockMultipartFile("data","data.json","application/json","{\"enabled\":true,\"requirePkce\":false,\"authorizationCodeTtl\":60}".getBytes());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart(org.springframework.http.HttpMethod.PUT,"/api/clients/"+c.getClientId()).file(update).file(png)
   .header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.data.enabled").value(true));
  c=clients.findByClientId(c.getClientId()).orElseThrow();assertFalse(c.isRequirePkce());assertEquals(60,c.getAuthorizationCodeTtl());
 }
 @Test void uploadRejectsEmptyOversizedDisguisedAndMismatchedImages() throws Exception {
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeAvatar(new org.springframework.mock.web.MockMultipartFile("file",new byte[0])));
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeAvatar(new org.springframework.mock.web.MockMultipartFile("file","x.png","image/png","<html>malicious</html>".getBytes())));
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeAvatar(new org.springframework.mock.web.MockMultipartFile("file","x.svg","image/svg+xml","<svg></svg>".getBytes())));
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeAvatar(new org.springframework.mock.web.MockMultipartFile("file","x.jpg","image/jpeg",image("png"))));
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeClientIcon(new org.springframework.mock.web.MockMultipartFile("icon","large.png","image/png",new byte[2*1024*1024+1])));
  assertThrows(IllegalArgumentException.class,()->uploadStorage.storeAvatar(new org.springframework.mock.web.MockMultipartFile("file","large.png","image/png",new byte[5*1024*1024+1])));
 }
 @Test void revokedJwtCannotFallBackToPreviouslyAuthenticatedHttpSession() throws Exception {
  var u=uploadUser("revoked-session-fallback");var request=new org.springframework.mock.web.MockHttpServletRequest();
  var device=auditSessions.create(u,request,"TEST");
  var principal=new io.aegis.passport.security.PassportUserPrincipal(u,java.util.Set.of("admin"),java.util.Set.of("*"));
  var context=org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
  context.setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(principal,null,principal.getAuthorities()));
  var session=(org.springframework.mock.web.MockHttpSession)request.getSession();session.setAttribute("SPRING_SECURITY_CONTEXT",context);
  auditSessions.revokeOwned(u.getId(),java.util.List.of(device.getId()),"test","TEST");
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile").session(session))
   .andExpect(status().isUnauthorized());
 }
 @Test void legacyJwtWithoutDeviceSessionMustRequireLogin() throws Exception {
  var u=uploadUser("legacy-jwt-regression");
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile")
   .header("Authorization","Bearer "+auditTokens.generate(u.getId(),u.getUsername()))).andExpect(status().isUnauthorized());
 }
 @Test void verifiedEmailChangesLoseVerificationAndUnknownOfflineIdsDoNotCount() {
  var u=users.save(User.builder().username("verified-email-reset").email("verified@example.invalid").emailVerified(true).password("test-only").build());
  var req=new io.aegis.passport.user.dto.UserDtos.UpdateProfileRequest(); req.setEmail("changed@example.invalid");
  assertFalse(auditUsers.updateProfile(u.getUsername(),req).isEmailVerified());
  assertEquals(0,auditSessions.deleteOwnedOffline(u.getId(),java.util.List.of("no-such-session")));
 }
 @Test void revokedAndLegacyJwtCannotObtainOAuthAuthorizationCode() throws Exception {
  var u=uploadUser("revoked-oauth-code-regression");
  var c=clients.save(OAuthClient.builder().clientId("revoked-oauth-code-client")
   .clientName("Revoked OAuth code test").clientSecret(encoder.encode("test-only"))
   .redirectUris("https://example.invalid/revocation-callback").requirePkce(false).requireConsent(false).build());
  var token=trackedToken(u);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  var active=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/authorize")
   .cookie(new jakarta.servlet.http.Cookie("__Host-passport-token",token)).header("Accept","text/html")
   .queryParam("client_id",c.getClientId()).queryParam("redirect_uri",c.getRedirectUris())
   .queryParam("response_type","code").queryParam("scope","openid").queryParam("state","revocation-test")
   .queryParam("aegis_account_confirmed","1")).andReturn();
  String redirect=active.getResponse().getRedirectedUrl();
  assertNotNull(redirect);assertTrue(redirect.startsWith(c.getRedirectUris())&&redirect.contains("code="),"active device must first obtain an authorization code");
  auditSessions.revokeOwned(u.getId(),java.util.List.of(auditTokens.extractSessionId(token)),"test","TEST");
  for(String invalidToken:java.util.List.of(token,auditTokens.generate(u.getId(),u.getUsername()))) {
   var rejected=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/authorize")
    .cookie(new jakarta.servlet.http.Cookie("__Host-passport-token",invalidToken)).header("Accept","text/html")
    .queryParam("client_id",c.getClientId()).queryParam("redirect_uri",c.getRedirectUris())
    .queryParam("response_type","code").queryParam("scope","openid").queryParam("state","revocation-test")
    .queryParam("aegis_account_confirmed","1")).andReturn();
   assertNotNull(rejected.getResponse().getRedirectedUrl());
   assertTrue(rejected.getResponse().getRedirectedUrl().contains("/auth/login"),"revoked or untracked JWT must require fresh login before OAuth code issuance");
  }
 }

 @Test void memberCanLoginWithUsernameAndEmailAndReadProfile() throws Exception {
  String password="member-login-test-only";
  var u=users.save(User.builder().username("member-login-regression").email("member-login@example.test")
   .password(encoder.encode(password)).primaryRole("member")
   .roles(java.util.Set.of(testRoles.findByCode("member").orElseThrow())).build());
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  for(String identifier:java.util.List.of(u.getUsername(),u.getEmail())) {
   var response=mvc.perform(post("/api/auth/login").contentType("application/json")
    .content("{\"username\":\""+identifier+"\",\"password\":\""+password+"\"}"))
    .andExpect(status().isOk()).andExpect(jsonPath("$.data.username").value(u.getUsername())).andReturn();
   var cookie=response.getResponse().getCookie("__Host-passport-token");assertNotNull(cookie);
   mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/user/profile").cookie(cookie))
    .andExpect(status().isOk()).andExpect(jsonPath("$.data.username").value(u.getUsername()))
    .andExpect(jsonPath("$.data.roles",org.hamcrest.Matchers.hasItem("member")));
   assertNotNull(users.findById(u.getId()).orElseThrow().getLastLoginAt());
  }
 }

 private io.aegis.passport.auth.dto.AuthDtos.RegisterRequest groupsRegistration(String name, java.util.Set<String> groups) {
  var req=new io.aegis.passport.auth.dto.AuthDtos.RegisterRequest();
  req.setUsername(name);req.setPassword("groups-regression-only-password");req.setGroups(groups);
  return req;
 }

 @Test void adminRegistrationPersistsMultipleGroupsAtomically() throws Exception {
  var admin=uploadUser("groups-registration-admin");var token=trackedToken(admin);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(post("/api/auth/register").header("Authorization","Bearer "+token).contentType("application/json")
   .content("{\"username\":\"groups-created-user\",\"password\":\"groups-test-only-password\",\"groups\":[\"member\",\"admin\"]}"))
   .andExpect(status().isOk());
  var created=users.findByUsername("groups-created-user").orElseThrow();
  assertEquals(java.util.Set.of("admin","member"),created.getRoles().stream().map(r->r.getCode()).collect(java.util.stream.Collectors.toSet()));
  assertEquals("admin",created.getPrimaryRole());
  mvc.perform(post("/api/auth/register").header("Authorization","Bearer "+token).contentType("application/json")
   .content("{\"username\":\"groups-invalid-user\",\"password\":\"groups-test-only-password\",\"groups\":[\"missing-group\"]}"))
   .andExpect(status().isNotFound());
  assertFalse(users.existsByUsername("groups-invalid-user"));
 }

 @Test void registrationNeverLetsNonAdminChoosePrivilegedGroups() throws Exception {
  var req=groupsRegistration("groups-no-self-elevation",java.util.Set.of("admin","member"));req.setRole("admin");
  var created=auditUsers.registerUser(req,false);
  assertEquals(java.util.Set.of("user"),created.getRoles().stream().map(r->r.getCode()).collect(java.util.stream.Collectors.toSet()));
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(post("/api/auth/register").contentType("application/json")
   .content("{\"username\":\"groups-public-denied\",\"password\":\"groups-test-only-password\",\"groups\":[\"admin\"]}"))
   .andExpect(status().isBadRequest());
  assertFalse(users.existsByUsername("groups-public-denied"));
 }

 @Test void registrationValidatesGroupsAndKeepsLegacyRoleClientsWorking() {
  assertThrows(RuntimeException.class,()->auditUsers.registerUser(groupsRegistration("groups-empty",java.util.Set.of()),true));
  assertThrows(RuntimeException.class,()->auditUsers.registerUser(groupsRegistration("groups-unknown",java.util.Set.of("missing-group")),true));
  assertFalse(users.existsByUsername("groups-empty"));assertFalse(users.existsByUsername("groups-unknown"));
  var req=groupsRegistration("groups-legacy-role",null);req.setRole("member");
  assertEquals("member",auditUsers.registerUser(req,true).getPrimaryRole());
  req=groupsRegistration("groups-explicit-wins",java.util.Set.of("member"));req.setRole("admin");
  assertEquals("member",auditUsers.registerUser(req,true).getPrimaryRole());
 }

 @Test void userEditSavesAllGroupsAndRollsBackInvalidSelections() {
  var user=auditUsers.registerUser(groupsRegistration("groups-edit-user",java.util.Set.of("member","admin")),true);
  var req=new io.aegis.passport.user.dto.UserDtos.AdminUpdateUserRequest();req.setGroups(java.util.Set.of("member","user"));req.setNickname("Groups edited");
  assertEquals(java.util.Set.of("member","user"),auditUsers.adminUpdateUser(user.getId(),req,encoder).getRoles());
  var invalid=new io.aegis.passport.user.dto.UserDtos.AdminUpdateUserRequest();invalid.setGroups(java.util.Set.of("missing-group"));invalid.setNickname("Must not persist");
  assertThrows(RuntimeException.class,()->auditUsers.adminUpdateUser(user.getId(),invalid,encoder));
  var unchanged=users.findByUsername(user.getUsername()).orElseThrow();
  assertEquals("Groups edited",unchanged.getNickname());
  assertEquals(java.util.Set.of("member","user"),unchanged.getRoles().stream().map(r->r.getCode()).collect(java.util.stream.Collectors.toSet()));
 }

 @Test void appAuthorsCanReadMinimalGroupChoicesWithoutRoleAdminAccess() throws Exception {
  var member=auditUsers.registerUser(groupsRegistration("groups-app-author",java.util.Set.of("member")),true);
  var basic=auditUsers.registerUser(groupsRegistration("groups-basic-reader",java.util.Set.of("user")),true);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/groups")
   .header("Authorization","Bearer "+trackedToken(member))).andExpect(status().isOk())
   .andExpect(jsonPath("$.data[*].code",org.hamcrest.Matchers.hasItems("admin","member","user")))
   .andExpect(jsonPath("$.data[0].permissions").doesNotExist());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/admin/roles")
   .header("Authorization","Bearer "+trackedToken(member))).andExpect(status().isForbidden());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/groups")
   .header("Authorization","Bearer "+trackedToken(basic))).andExpect(status().isForbidden());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/groups"))
   .andExpect(status().isUnauthorized());
 }

 @Test void appGroupsAreNormalizedValidatedAndCanBeCleared() throws Exception {
  users.save(User.builder().username("groups-app-owner").password(encoder.encode("test-only")).build());
  var req=new OAuthClientService.ClientRequest("Groups application",null,"https://example.invalid/groups-callback",
   "authorization_code","openid",900,3600,300,false,false," member, admin,member ",null,null);
  var created=service.create(req,null,"groups-app-owner",false);
  assertEquals("admin,member",clients.findByClientId(created.getClientId()).orElseThrow().getAllowedRoles());
  var invalid=new OAuthClientService.ClientRequest("Groups invalid",null,"https://example.invalid/groups-callback",
   "authorization_code","openid",900,3600,300,false,false,"missing-group",null,null);
  long before=clients.count();assertThrows(RuntimeException.class,()->service.create(invalid,null,"groups-app-owner",false));assertEquals(before,clients.count());
  var clear=new OAuthClientService.ClientRequest("Groups application",null,"https://example.invalid/groups-callback",
   "authorization_code","openid",900,3600,300,false,false,"",null,null);
  service.update(created.getClientId(),clear,null,"groups-app-owner",false);
  assertEquals("",clients.findByClientId(created.getClientId()).orElseThrow().getAllowedRoles());
 }

 @Test void selectedGroupControlsOAuthAccessAndAppearsInSignedIdTokenWithoutProfile() throws Exception {
  var member=auditUsers.registerUser(groupsRegistration("groups-oidc-member",java.util.Set.of("member")),true);
  var basic=auditUsers.registerUser(groupsRegistration("groups-oidc-basic",java.util.Set.of("user")),true);
  users.save(User.builder().username("groups-oidc-owner").password(encoder.encode("test-only")).build());
  var req=new OAuthClientService.ClientRequest("Groups OIDC flow",null,"https://example.invalid/groups-oidc-callback",
   "authorization_code","openid",900,3600,300,false,false,"member",null,null);
  var client=service.create(req,null,"groups-oidc-owner",false);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();
  String code=null;
  for(var user:java.util.List.of(basic,member)) {
   var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/authorize")
    .cookie(new jakarta.servlet.http.Cookie("__Host-passport-token",trackedToken(user))).header("Accept","text/html")
    .queryParam("client_id",client.getClientId()).queryParam("redirect_uri",client.getRedirectUris())
    .queryParam("response_type","code").queryParam("scope","openid").queryParam("state","groups-test")
    .queryParam("aegis_account_confirmed","1")).andReturn().getResponse();
   var redirect=response.getRedirectedUrl();assertNotNull(redirect);
   if(user==basic) {assertTrue(redirect.contains("denied=1"));}
   else {assertTrue(redirect.startsWith(client.getRedirectUris())&&redirect.contains("code="));
    code=org.springframework.web.util.UriComponentsBuilder.fromUriString(redirect).build().getQueryParams().getFirst("code");}
  }
  var result=mvc.perform(post("/oauth2/token").with(httpBasic(client.getClientId(),client.getClientSecret()))
   .param("grant_type","authorization_code").param("code",code).param("redirect_uri",client.getRedirectUris()))
   .andExpect(status().isOk()).andExpect(jsonPath("$.id_token").isString()).andReturn();
  var response=new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getResponse().getContentAsString());
  var claims=com.nimbusds.jwt.SignedJWT.parse(response.get("id_token").asText()).getJWTClaimsSet();
  assertEquals(java.util.List.of("member"),claims.getStringListClaim("groups"));
  assertNull(claims.getClaim("role"));
 }
}
