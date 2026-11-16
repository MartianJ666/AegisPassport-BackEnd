package io.aegis.passport;

import io.aegis.passport.auth.*;
import io.aegis.passport.client.*;
import io.aegis.passport.email.EmailService;
import io.aegis.passport.external.*;
import io.aegis.passport.session.*;
import io.aegis.passport.security.*;
import io.aegis.passport.systemconfig.SystemConfigService;
import io.aegis.passport.user.*;
import io.aegis.passport.user.entity.User;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.event.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.test.web.servlet.*;
import org.springframework.mock.web.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@SpringBootTest @ActiveProfiles("local") @Transactional @RecordApplicationEvents
@TestPropertySource(properties={"spring.datasource.url=jdbc:h2:mem:core-regression;MODE=MySQL;DB_CLOSE_DELAY=-1","spring.flyway.enabled=false","spring.jpa.hibernate.ddl-auto=create-drop","passport.jwt.secret=core-test-only-secret-at-least-thirty-two-characters","passport.bootstrap-admin.password=core-test-only-password","passport.upload.dir=build/test-uploads"})
class OriginalCoreRegressionTests {
 @Autowired org.springframework.web.context.WebApplicationContext web;
 @Autowired UserRepository users;
 @Autowired UserService service;
 @Autowired VerificationCodeService codes;
 @Autowired SessionService sessions;
 @Autowired JwtTokenProvider tokens;
 @Autowired SystemConfigService config;
 @Autowired ExternalLoginService external;
 @Autowired ApplicationEvents events;
 @MockitoBean EmailService email;
 MockMvc mvc;
 @BeforeEach void setup(){mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(web).apply(springSecurity()).build();when(email.isEnabled()).thenReturn(true);}
 private User account(String username){var request=new io.aegis.passport.auth.dto.AuthDtos.RegisterRequest();request.setUsername(username);request.setPassword("fixture-password");request.setGroups(Set.of("admin"));return service.registerUser(request,true);}
 private String jwt(User u,AuthSession session){return tokens.generate(u.getId(),u.getUsername(),session.getId());}
 @Test void publicRegistrationWorksButCannotAssignAdminGroups() throws Exception {
  String code=codes.generate("registration@example.invalid");
  mvc.perform(post("/api/auth/register").contentType("application/json").content("{\"username\":\"public-registration\",\"email\":\"registration@example.invalid\",\"verificationCode\":\""+code+"\",\"password\":\"fixture-password\",\"groups\":[\"admin\"],\"role\":\"admin\"}"))
   .andExpect(status().isOk());
  var u=users.findByUsername("public-registration").orElseThrow();assertEquals("user",u.getPrimaryRole());assertEquals(Set.of("user"),u.getRoles().stream().map(x->x.getCode()).collect(java.util.stream.Collectors.toSet()));assertTrue(u.isEmailVerified());assertFalse(codes.verify(u.getEmail(),code));
 }
 @Test void invalidCodeCannotCreateAccountAndMissingMailRemainsClear() throws Exception {
  mvc.perform(post("/api/auth/register").contentType("application/json").content("{\"username\":\"invalid-registration\",\"email\":\"invalid@example.invalid\",\"verificationCode\":\"000000\",\"password\":\"fixture-password\"}"))
   .andExpect(status().isBadRequest()).andExpect(jsonPath("$.errorCode").value("VERIFICATION_CODE_INVALID"));assertFalse(users.existsByUsername("invalid-registration"));
  when(email.isEnabled()).thenReturn(false);
  mvc.perform(post("/api/auth/register").contentType("application/json").content("{\"username\":\"no-mail-registration\",\"password\":\"fixture-password\"}"))
   .andExpect(status().isBadRequest()).andExpect(jsonPath("$.errorCode").value("EMAIL_NOT_CONFIGURED"));
 }
 @Test void firstExternalLoginCreatesSetupAccountWithVerifiedEmail() {
  var request=new MockHttpServletRequest();request.addHeader("X-Device-ID","external-fixture-device-12345");var response=new MockHttpServletResponse();
  boolean needsSetup=external.authenticate(new ExternalProviderIdentity("oidc","https://identity.example.com","first-subject","New User",null,"new-user@example.invalid"),request,response);
  assertTrue(needsSetup);var u=users.findByEmail("new-user@example.invalid").orElseThrow();assertTrue(u.isNeedsSetup());assertTrue(u.isEmailVerified());assertEquals("user",u.getPrimaryRole());assertNull(u.getOrganizationId());assertNotNull(response.getCookie("__Host-passport-token"));
 }
 @Test void singleDeviceReplacementRevokesTheOldDeviceAndPublishesOAuthRevocation() {
  var u=account("single-device-regression");var old=sessions.create(u,new MockHttpServletRequest(),"TEST");assertTrue(sessions.active(old.getId(),u.getId()));config.setAllowMultipleDevices(false);
  var latest=sessions.create(u,new MockHttpServletRequest(),"TEST");assertFalse(sessions.active(old.getId(),u.getId()));assertTrue(sessions.active(latest.getId(),u.getId()));
  assertTrue(events.stream(SessionService.RevokedSessions.class).anyMatch(x->x.sessionIds().contains(old.getId())));
 }
 @Test void changingPasswordKeepsCurrentDeviceAndRevokesOtherDevices() throws Exception {
  var u=account("change-password-regression");var current=sessions.create(u,new MockHttpServletRequest(),"TEST");var other=sessions.create(u,new MockHttpServletRequest(),"TEST");
  mvc.perform(post("/api/user/change-password").header("Authorization","Bearer "+jwt(u,current)).contentType("application/json").content("{\"oldPassword\":\"fixture-password\",\"newPassword\":\"new-fixture-password\"}"))
   .andExpect(status().isOk());assertTrue(sessions.active(current.getId(),u.getId()));assertFalse(sessions.active(other.getId(),u.getId()));
 }
 @Test void genericDisplaySettingsArePublicButMutationRequiresPermission() throws Exception {
  mvc.perform(get("/api/config/login")).andExpect(status().isOk()).andExpect(jsonPath("$.data.backgroundMode").value("color"));
  mvc.perform(post("/api/config/admin/login-background").contentType("application/json").content("{\"backgroundMode\":\"color\"}")).andExpect(status().isUnauthorized());
  assertThrows(io.aegis.passport.common.exception.BusinessException.class,()->config.saveBackground(List.of("https://untrusted.example/image.png"),null,null,null));
  assertThrows(io.aegis.passport.common.exception.BusinessException.class,()->config.saveBackground(null,"invalid",null,null));
  config.saveBackground(List.of("/uploads/backgrounds/12345678-abcd-abcd-abcd-123456789abc.png"),"single",4,"#112233");assertEquals("single",config.getBackgroundMode());assertEquals(1,config.getBackgroundImages().size());
 }
 @Test void announcementEditorRejectsInvalidContentAndCanClearScheduledWindow() throws Exception {
  var u=account("announcement-editor");String token=jwt(u,sessions.create(u,new MockHttpServletRequest(),"TEST"));
  mvc.perform(post("/api/admin/announcements").header("Authorization","Bearer "+token).contentType("application/json").content("{\"content\":\"body\"}")).andExpect(status().isBadRequest());
  var result=mvc.perform(post("/api/admin/announcements").header("Authorization","Bearer "+token).contentType("application/json").content("{\"title\":\"Scheduled\",\"content\":\"Body\",\"startTime\":\"2030-01-01T00:00:00Z\",\"endTime\":\"2030-02-01T00:00:00Z\"}"))
    .andExpect(status().isOk()).andExpect(jsonPath("$.data.level").value("info")).andReturn();
  long id=new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getResponse().getContentAsString()).path("data").path("id").asLong();
  mvc.perform(put("/api/admin/announcements/"+id).header("Authorization","Bearer "+token).contentType("application/json").content("{\"title\":\"Immediate\",\"startTime\":null,\"endTime\":null}"))
    .andExpect(status().isOk()).andExpect(jsonPath("$.data.startTime").isEmpty()).andExpect(jsonPath("$.data.endTime").isEmpty());
 }
}
