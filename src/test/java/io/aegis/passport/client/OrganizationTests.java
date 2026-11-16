package io.aegis.passport.client;

import io.aegis.passport.organization.*;
import io.aegis.passport.organization.entity.Organization;
import io.aegis.passport.user.*;
import io.aegis.passport.user.entity.User;
import io.aegis.passport.user.dto.UserDtos.*;
import io.aegis.passport.auth.dto.AuthDtos.RegisterRequest;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.exception.BusinessException;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest @ActiveProfiles("local")
@TestPropertySource(properties={
 "spring.datasource.url=jdbc:h2:mem:organization-regression;MODE=MySQL;DB_CLOSE_DELAY=-1",
 "spring.flyway.enabled=false", "spring.jpa.hibernate.ddl-auto=create-drop",
 "passport.bootstrap-admin.password=local-regression-only-password",
 "passport.jwt.secret=local-regression-only-secret-at-least-32bytes",
 "passport.upload.dir=build/test-uploads",
 "passport.oidc.key-dir=build/test-keys"
})
@Transactional
class OrganizationTests {
 @Autowired OrganizationService organizations;
 @Autowired OrganizationRepository orgRepo;
 @Autowired UserService userService;
 @Autowired UserRepository users;
 @Autowired OAuthClientRepository clients;
 @Autowired PasswordEncoder encoder;
 @Autowired OAuthClientService clientService;
 @Autowired org.springframework.web.context.WebApplicationContext web;
 @Autowired io.aegis.passport.session.SessionService sessions;
 @Autowired io.aegis.passport.security.JwtTokenProvider tokens;
 @Autowired io.aegis.passport.oauth.OidcUserInfoMapper userInfo;
 private String token(User u){var session=sessions.create(u,new org.springframework.mock.web.MockHttpServletRequest(),"TEST");return tokens.generate(u.getId(),u.getUsername(),session.getId());}
 private Organization org(String name){return orgRepo.saveAndFlush(Organization.builder().name(name).build());}
 private User user(String name){return users.saveAndFlush(User.builder().username(name).password(encoder.encode("test-only")).build());}

 @Test void createSelectRenameAndClearOrganizationKeepsRoleSeparate(){
  var o=org("Organization regression");var req=new RegisterRequest();req.setUsername("org-new-user");req.setPassword("test-only");req.setGroups(Set.of("user","member"));req.setOrganizationId(o.getId());req.setEnabled(false);
  var u=userService.registerUser(req,true);assertEquals(o.getName(),u.getOrgName());assertEquals(o.getId(),u.getOrganizationId());assertFalse(u.isEnabled());assertEquals(2,u.getRoles().size());
  organizations.save(o.getId(),"Renamed organization","");
  assertEquals("Renamed organization",userService.getByUsername(u.getUsername()).getOrgName());
  var update=new AdminUpdateUserRequest();update.setOrganizationId(0L);userService.adminUpdateUser(u.getId(),update,encoder);
  assertNull(users.findById(u.getId()).orElseThrow().getOrganizationId());assertNull(users.findById(u.getId()).orElseThrow().getOrgName());
 }
 @Test void unknownOrganizationAndFreeTextAreRejected(){
  var u=user("org-invalid-target");var req=new AdminUpdateUserRequest();req.setOrganizationId(999999L);
  assertThrows(BusinessException.class,()->userService.adminUpdateUser(u.getId(),req,encoder));
  var register=new RegisterRequest();register.setUsername("org-free-text");register.setPassword("test-only");register.setOrgName("invented organization");
  assertThrows(BusinessException.class,()->userService.registerUser(register,true));
 }
 @Test void selfProfileCannotAssignOrSpoofOrganization(){
  var u=user("org-self-profile");var o=org("Protected organization");organizations.setMember(o.getId(),u.getId(),true);
  var req=new UpdateProfileRequest();req.setOrganizationId(o.getId());assertThrows(BusinessException.class,()->userService.updateProfile(u.getUsername(),req));
  req.setOrganizationId(null);req.setOrgName("Admin organization");assertThrows(BusinessException.class,()->userService.updateProfile(u.getUsername(),req));
 }
 @Test void membershipMoveDoesNotChangeRolesAndOldRemovalCannotRemoveNewMembership(){
  var u=user("org-move-member");var a=org("Move from");var b=org("Move to");
  userService.assignRoles(u.getId(),Set.of("member"));organizations.setMember(a.getId(),u.getId(),true);organizations.setMember(b.getId(),u.getId(),true);organizations.setMember(a.getId(),u.getId(),false);
  var view=userService.getByUsername(u.getUsername());assertEquals(b.getId(),view.getOrganizationId());assertEquals(Set.of("member"),view.getRoles());
 }
 @Test void referencedOrganizationCannotBeDeletedAndRestrictionDoesNotDisappear(){
  var o=org("Referenced organization");var c=clients.save(OAuthClient.builder().clientId("org-reference-client").clientName("Referenced app").clientSecret("test-only").redirectUris("https://example.invalid/callback").organizationRestricted(true).allowedOrganizations(o.getId().toString()).build());
  assertThrows(BusinessException.class,()->organizations.delete(o.getId()));
  organizations.setApps(o.getId(),Map.of(c.getClientId(),false));
  assertTrue(clients.findByClientId(c.getClientId()).orElseThrow().isOrganizationRestricted());
  assertFalse(ClientAccessPolicy.organizationAllowed(clients.findByClientId(c.getClientId()).orElseThrow(),o.getId()));
 }
 @Test void organizationApplicationChangesDoNotOverwriteRoleOrPersonalRules(){
  var o=org("Independent gate");var c=clients.save(OAuthClient.builder().clientId("org-independent-client").clientName("Independent app").clientSecret("test-only").redirectUris("https://example.invalid/callback").allowedRoles("admin").allowedUsers("7").deniedUsers("8").build());
  organizations.setApps(o.getId(),Map.of(c.getClientId(),false));
  var actual=clients.findByClientId(c.getClientId()).orElseThrow();assertEquals("admin",actual.getAllowedRoles());assertEquals("7",actual.getAllowedUsers());assertEquals("8",actual.getDeniedUsers());assertFalse(ClientAccessPolicy.organizationAllowed(actual,o.getId()));
  assertTrue(ClientAccessPolicy.organizationAllowed(actual,999L));
  organizations.setApps(o.getId(),Map.of(c.getClientId(),true));assertTrue(ClientAccessPolicy.organizationAllowed(actual,o.getId()));
 }
 @Test void duplicateNamesAndMembersPreventDeletingOrganization(){
  var o=organizations.save(null,"Unique organization","");assertThrows(BusinessException.class,()->organizations.save(null," Unique organization ",""));
  var u=user("org-not-empty");organizations.setMember(o.id(),u.getId(),true);assertThrows(BusinessException.class,()->organizations.delete(o.id()));
 }
 @Test void adminEmailDuplicateReturnsBusinessErrorAndPreservesExistingEmail(){
  var a=user("org-email-a");a.setEmail("taken@example.invalid");users.saveAndFlush(a);var b=user("org-email-b");var req=new AdminUpdateUserRequest();req.setEmail(a.getEmail());
  assertThrows(BusinessException.class,()->userService.adminUpdateUser(b.getId(),req,encoder));
 }
 @Test void organizationAdministrationRequiresPermissionsAndClaimsStayDistinct() throws Exception {
  var request=new RegisterRequest();request.setUsername("org-api-admin");request.setPassword("test-only");request.setGroups(Set.of("admin"));
  var admin=userService.registerUser(request,true);request.setUsername("org-api-basic");request.setGroups(Set.of("user"));var basic=userService.registerUser(request,true);
  var organization=org("API organization");organizations.setMember(organization.getId(),basic.getId(),true);
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity()).build();
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/organizations")).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isUnauthorized());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/organizations").header("Authorization","Bearer "+token(basic))).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/organizations").header("Authorization","Bearer "+token(admin))).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk()).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.data[0].name").value(organization.getName()));
  mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/api/organizations/"+organization.getId()+"/members/"+admin.getId()).header("Authorization","Bearer "+token(basic)).contentType("application/json").content("{\"member\":true}")).andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
  var claims=userInfo.map(basic.getUsername(),Set.of("openid","groups","organization")).getClaims();
  assertEquals(List.of("user"),claims.get("groups"));assertEquals(organization.getId(),claims.get("organization_id"));assertEquals(organization.getName(),claims.get("organization_name"));
  assertFalse(userInfo.map(basic.getUsername(),Set.of("openid")).getClaims().containsKey("organization_id"));
 }
 @Test void oauthAuthorizeAdminGrantOverridesOrganization() throws Exception {
  var request=new RegisterRequest();request.setUsername("org-oidc-member");request.setPassword("test-only");request.setGroups(Set.of("member"));var member=userService.registerUser(request,true);
  var a=org("OIDC organization A");var b=org("OIDC organization B");organizations.setMember(b.getId(),member.getId(),true);
  var client=clients.saveAndFlush(OAuthClient.builder().clientId("org-oidc-client").clientName("Organization OIDC app").clientSecret(encoder.encode("test-only")).redirectUris("https://example.invalid/org-callback").requirePkce(false).requireConsent(false).organizationRestricted(true).allowedOrganizations(a.getId().toString()).build());
  var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity()).build();
  var jwt=token(member);
  for(boolean allowed:List.of(false,true)) {
   if(allowed){client.setAllowedUsers(member.getId().toString());clients.saveAndFlush(client);}
   var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/authorize").cookie(new jakarta.servlet.http.Cookie("__Host-passport-token",jwt)).header("Accept","text/html").queryParam("client_id",client.getClientId()).queryParam("redirect_uri",client.getRedirectUris()).queryParam("response_type","code").queryParam("scope","openid").queryParam("state","organization-test").queryParam("aegis_account_confirmed","1")).andReturn().getResponse();
   var redirect=response.getRedirectedUrl();assertNotNull(redirect);assertTrue(redirect.contains(allowed?"code=":"denied=1"),redirect);
  }
 }
}

