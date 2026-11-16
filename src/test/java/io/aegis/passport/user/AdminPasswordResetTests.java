package io.aegis.passport.user;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import io.aegis.passport.security.RsaTransportService;
import io.aegis.passport.session.AuthSessionRepository;
import io.aegis.passport.common.exception.BusinessException;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

class AdminPasswordResetTests {
    final RsaTransportService rsa=mock(RsaTransportService.class);
    final PasswordEncoder encoder=mock(PasswordEncoder.class);
    final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    final AuthSessionRepository sessions=mock(AuthSessionRepository.class);
    final AdminPasswordResetController controller=new AdminPasswordResetController(rsa,encoder,jdbc,sessions);
    @Test void invalidEncryptionCannotChangePassword() {
        when(rsa.decryptStrict(any())).thenThrow(new IllegalArgumentException());
        assertThrows(BusinessException.class,()->controller.reset(8L,new AdminPasswordResetController.ResetRequest("bad","bad")));
        verifyNoInteractions(jdbc,sessions);
    }
    @Test void mismatchCannotChangePassword() {
        when(rsa.decryptStrict("a")).thenReturn("abcdef");when(rsa.decryptStrict("b")).thenReturn("different");
        assertThrows(BusinessException.class,()->controller.reset(8L,new AdminPasswordResetController.ResetRequest("a","b")));
        verifyNoInteractions(jdbc,sessions);
    }
    @Test void validResetHashesAndRevokesOnlyTargetSessions() {
        when(rsa.decryptStrict(any())).thenReturn("abcdef");when(encoder.encode("abcdef")).thenReturn("hash");
        when(jdbc.update(anyString(),any(Object[].class))).thenReturn(1);
        controller.reset(8L,new AdminPasswordResetController.ResetRequest("a","b"));
        verify(encoder).encode("abcdef");
        verify(sessions).revokeActiveForUserExcept(eq(8L),eq("__none__"),any(),eq("ADMIN_PASSWORD_RESET"),nullable(String.class));
    }
}
