package io.aegis.passport.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import io.aegis.passport.audit.AuditLogService;
import io.aegis.passport.auth.dto.AuthDtos.LoginRequest;
import io.aegis.passport.email.EmailService;
import io.aegis.passport.security.JwtTokenProvider;
import io.aegis.passport.security.PassportUserPrincipal;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.session.SessionService;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.UserService;
import io.aegis.passport.user.entity.User;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

class PasswordLoginSessionTests {
    final UserService users = mock(UserService.class);
    final AuthenticationManager auth = mock(AuthenticationManager.class);
    final JwtTokenProvider jwt = mock(JwtTokenProvider.class);
    final RsaTransportService rsa = mock(RsaTransportService.class);
    final LoginAttemptService attempts = mock(LoginAttemptService.class);
    final UserRepository repository = mock(UserRepository.class);
    final SessionService sessions = mock(SessionService.class);
    final AuthController controller = new AuthController(users, auth, jwt, rsa, attempts,
            mock(VerificationCodeService.class), mock(EmailService.class), mock(AuditLogService.class),
            repository, sessions);
    final User user = User.builder().id(7L).username("session-test").password("hash").enabled(true).build();
    final LoginRequest login = new LoginRequest();
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();

    @BeforeEach void setup() {
        login.setUsername(user.getUsername());
        login.setPassword("encrypted");
        when(rsa.decrypt("encrypted")).thenReturn("password");
        var principal = new PassportUserPrincipal(user, List.of("USER"), List.of());
        when(auth.authenticate(any())).thenReturn(
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
        when(repository.findById(user.getId())).thenReturn(Optional.of(user));
        when(sessions.create(user, request, "PASSWORD")).thenReturn(io.aegis.passport.session.AuthSession.builder().id("test-session").build());
        when(jwt.generate(user.getId(), user.getUsername(), "test-session")).thenReturn("test-token");
    }

    @AfterEach void cleanup() { SecurityContextHolder.clearContext(); }

    @Test void passwordLoginRegistersDeviceSessionAndKeepsLoginResponse() {
        var result = controller.login(login, request, response);
        verify(sessions).create(user, request, "PASSWORD");
        assertEquals("test-token", result.getBody().getData().getToken());
        assertNotNull(request.getSession(false).getAttribute("SPRING_SECURITY_CONTEXT"));
        assertEquals("test-token", response.getCookie("__Host-passport-token").getValue());
        assertTrue(response.getCookie("__Host-passport-token").getSecure());
        assertEquals("Lax", response.getCookie("__Host-passport-token").getAttribute("SameSite"));
    }

    @Test void sessionRegistrationFailureMustNotIssueUnrevocableCredentials() {
        when(sessions.create(user, request, "PASSWORD")).thenThrow(new IllegalStateException("test failure"));
        var failure = assertThrows(io.aegis.passport.common.exception.BusinessException.class,
                () -> controller.login(login, request, response));
        assertEquals(io.aegis.passport.common.exception.ErrorCode.LOGIN_SESSION_UNAVAILABLE, failure.getErrorCode());
        verifyNoInteractions(jwt);
        verify(users, never()).recordLogin(any());
        assertNull(response.getCookie("__Host-passport-token"));
    }

    @Test void loginResolvedByEmailUsesAuthenticatedPrincipalId() {
        login.setUsername("member@example.test");
        var result = controller.login(login, request, response);
        assertEquals("test-token", result.getBody().getData().getToken());
        verify(repository).findById(user.getId());
        verify(users).recordLogin(user.getUsername());
        verify(sessions).create(user, request, "PASSWORD");
    }

    @Test void authenticationInfrastructureFailureDoesNotCountAsWrongPassword() {
        when(auth.authenticate(any())).thenThrow(
                new org.springframework.security.authentication.InternalAuthenticationServiceException("test database unavailable"));
        var failure = assertThrows(io.aegis.passport.common.exception.BusinessException.class,
                () -> controller.login(login, request, response));
        assertEquals(io.aegis.passport.common.exception.ErrorCode.LOGIN_SERVICE_UNAVAILABLE, failure.getErrorCode());
        verify(attempts, never()).loginFailed(any());
        verifyNoInteractions(jwt, sessions);
        assertNull(response.getCookie("__Host-passport-token"));
    }
}
