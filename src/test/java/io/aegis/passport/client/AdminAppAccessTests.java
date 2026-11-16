package io.aegis.passport.client;
import io.aegis.passport.user.*;
import io.aegis.passport.user.entity.User;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.auth.dto.AuthDtos.RegisterRequest;
import io.aegis.passport.common.exception.BusinessException;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest @ActiveProfiles("local")
@TestPropertySource(properties={"spring.datasource.url=jdbc:h2:mem:admin-grant-regression;MODE=MySQL;DB_CLOSE_DELAY=-1","spring.flyway.enabled=false","spring.jpa.hibernate.ddl-auto=create-drop","passport.bootstrap-admin.password=local-regression-only-password","passport.jwt.secret=local-regression-only-secret-at-least-32bytes","passport.upload.dir=build/test-uploads","passport.oidc.key-dir=build/test-keys"})
@Transactional
class AdminAppAccessTests {
 @Autowired AdminAppAccessService grants; @Autowired OAuthClientRepository clients;
 @Autowired UserRepository users; @Autowired UserService userService; @Autowired OAuthClientService clientService;
 @Autowired jakarta.persistence.EntityManager em;
 @Autowired org.springframework.web.context.WebApplicationContext web;
 @Autowired io.aegis.passport.session.SessionService sessions; @Autowired io.aegis.passport.security.JwtTokenProvider tokens;
 private User user(String name,String role){var r=new RegisterRequest();r.setUsername(name);r.setPassword("test-only-password");r.setGroups(Set.of(role));return userService.registerUser(r,true);}
 private OAuthClient app(String id,User owner){return clients.saveAndFlush(OAuthClient.builder().clientId(id).clientName(id).clientSecret("test-only").redirectUris("https://example.invalid/callback").owner(owner).allowedRoles("admin").organizationRestricted(true).build());}
 private String token(User u){var s=sessions.create(u,new org.springframework.mock.web.MockHttpServletRequest(),"TEST");return tokens.generate(u.getId(),u.getUsername(),s.getId());}
 @Test void temporaryPermanentAndRevokedGrantsPersistAndRespectExpiry(){
  var u=user("grant-temporary","user");var c=app("grant-temp-app",u);assertFalse(ClientAccessPolicy.allowed(c,u));
  var start=Instant.now();var view=grants.set(u.getId(),c.getClientId(),"allow",2);assertEquals("allow",view.mode());assertNotNull(view.expiresAt());assertTrue(view.expiresAt().isAfter(start.plusSeconds(7199)));assertTrue(view.effectiveAllowed());
  em.clear();c=clients.findByClientId(c.getClientId()).orElseThrow();assertTrue(ClientAccessPolicy.allowed(c,users.findById(u.getId()).orElseThrow()));
  var expiry=new HashMap<>(c.getAllowedUserExpirations());expiry.put(u.getId().toString(),Instant.now().minusSeconds(1).toEpochMilli());c.setAllowedUserExpirations(expiry);clients.saveAndFlush(c);
  var expired=grants.list(u.getId()).getFirst();assertTrue(expired.expired());assertEquals("default",expired.mode());assertFalse(expired.effectiveAllowed());
  var permanent=grants.set(u.getId(),c.getClientId(),"allow",null);assertNull(permanent.expiresAt());assertTrue(permanent.effectiveAllowed());
  assertFalse(grants.set(u.getId(),c.getClientId(),"default",null).effectiveAllowed());
 }
 @Test void expiryBoundaryAndFallbackUseRulesWithoutSleeping(){
  var u=user("grant-boundary","user");var c=app("grant-boundary-app",u);c.setAllowedUsers(u.getId().toString());var now=Instant.now();c.setAllowedUserExpirations(Map.of(u.getId().toString(),now.toEpochMilli()));
  assertFalse(ClientAccessPolicy.individualGrantActive(c,u.getId().toString(),now));assertTrue(ClientAccessPolicy.individualGrantActive(c,u.getId().toString(),now.minusMillis(1)));
  c.setOrganizationRestricted(false);c.setAllowedRoles("user");assertTrue(ClientAccessPolicy.allowed(c,u));
  c.setDeniedUsers(u.getId().toString());assertFalse(ClientAccessPolicy.allowed(c,u));
 }
 @Test void grantCannotBypassDisabledAppOrAccountOrExplicitDeny(){
  var u=user("grant-disabled","user");var c=app("grant-disabled-app",u);grants.set(u.getId(),c.getClientId(),"allow",1);
  c.setEnabled(false);assertFalse(ClientAccessPolicy.allowed(c,u));c.setEnabled(true);u.setEnabled(false);assertFalse(ClientAccessPolicy.allowed(c,u));u.setEnabled(true);u.setLocked(true);assertFalse(ClientAccessPolicy.allowed(c,u));u.setLocked(false);u.setBannedUntil(Instant.now().plusSeconds(60));assertFalse(ClientAccessPolicy.allowed(c,u));
 }
 @Test void invalidDurationsDoNotWriteGrants(){
  var u=user("grant-invalid","user");var c=app("grant-invalid-app",u);
  for(int h:List.of(0,-1,8761))assertThrows(BusinessException.class,()->grants.set(u.getId(),c.getClientId(),"allow",h));
  assertFalse(grants.list(u.getId()).getFirst().effectiveAllowed());
 }
 @Test void onlyAdministratorCanGrantAndLegacyAppOwnerCannotBypassEndpoint() throws Exception {
  var admin=user("grant-admin","admin");var member=user("grant-member","member");var target=user("grant-target","user");var c=app("grant-owner-app",member);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity()).build();
  String path="/api/admin/users/"+target.getId()+"/app-access/"+c.getClientId();
  mvc.perform(put(path).param("mode","allow").param("hours","2")).andExpect(status().isUnauthorized());
  mvc.perform(put(path).header("Authorization","Bearer "+token(member)).param("mode","allow").param("hours","2")).andExpect(status().isForbidden());
  var direct=new OAuthClientService.ClientRequest(null,null,null,null,null,null,null,null,null,null,null,target.getId().toString(),null);
  assertThrows(BusinessException.class,()->clientService.update(c.getClientId(),direct,null,member.getUsername(),false));
  mvc.perform(put(path).header("Authorization","Bearer "+token(admin)).param("mode","allow").param("hours","2")).andExpect(status().isOk()).andExpect(jsonPath("$.data.mode").value("allow")).andExpect(jsonPath("$.data.effectiveAllowed").value(true));
  mvc.perform(get("/api/admin/users/"+target.getId()+"/app-access").header("Authorization","Bearer "+token(admin))).andExpect(status().isOk()).andExpect(jsonPath("$.data[0].expiresAt").isString()).andExpect(jsonPath("$.data[0].clientSecret").doesNotExist());
 }
}
