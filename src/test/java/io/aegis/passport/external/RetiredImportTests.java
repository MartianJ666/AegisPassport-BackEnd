package io.aegis.passport.external;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.external.entity.ExternalAuthTransaction;
import io.aegis.passport.user.entity.User;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class RetiredImportTests {
    @Test void anOutstandingLegacyImportCannotBeReinterpretedAsAccountLinkOrLogin() {
        var config = mock(ThirdPartyLoginConfigService.class);
        var transactions = mock(ExternalAuthTransactionService.class);
        var login = mock(ExternalLoginService.class);
        var accounts = mock(ExternalAccountService.class);
        when(config.isEnabledAndReady("oidc")).thenReturn(true);
        when(transactions.consume("oidc", "tx", "state", "cookie"))
                .thenReturn(ExternalAuthTransaction.builder().intent("RETIRED_IMPORT")
                        .user(User.builder().id(8L).build()).build());
        var service = new ExternalProviderAuthService(config, transactions, login, accounts, new JsonMapper());
        assertThrows(BusinessException.class,
                () -> service.complete("oidc", "tx", "state", "code", null, "cookie", null, null));
        verifyNoInteractions(login, accounts);
    }

    @Test void oidcLoginRequestsStandardScopesAndPkce() {
        var config = mock(ThirdPartyLoginConfigService.class);
        var transactions = mock(ExternalAuthTransactionService.class);
        when(config.isEnabledAndReady("oidc")).thenReturn(true);
        when(config.runtime("oidc")).thenReturn(new ThirdPartyLoginConfigService.ProviderRuntime(
                "oidc", true, "client", "secret", "https://auth.example.com/callback", "https://identity.example.com"));
        when(transactions.random(48)).thenReturn("verifier");
        when(transactions.random(24)).thenReturn("nonce");
        when(transactions.create("oidc", "verifier", "nonce", null, "LOGIN"))
                .thenReturn(new ExternalAuthTransactionService.Start("tx", "state", "cookie", "verifier", "nonce"));
        var service = new ExternalProviderAuthService(config, transactions, mock(ExternalLoginService.class),
                mock(ExternalAccountService.class), new JsonMapper());
        var transport = mock(java.net.http.HttpClient.class);
        @SuppressWarnings("unchecked") var discovery = (java.net.http.HttpResponse<String>)mock(java.net.http.HttpResponse.class);
        when(discovery.statusCode()).thenReturn(200);
        when(discovery.body()).thenReturn("{\"issuer\":\"https://identity.example.com\",\"authorization_endpoint\":\"https://identity.example.com/authorize\",\"token_endpoint\":\"https://identity.example.com/token\"}");
        try { when(transport.send(any(java.net.http.HttpRequest.class), org.mockito.ArgumentMatchers.<java.net.http.HttpResponse.BodyHandler<String>>any())).thenReturn(discovery); }
        catch(Exception impossible) { throw new AssertionError(impossible); }
        org.springframework.test.util.ReflectionTestUtils.setField(service,"http",transport);
        var result = service.start("oidc");
        assertTrue(result.url().startsWith("https://identity.example.com/authorize?"));
        assertTrue(result.url().contains("scope=openid+profile+email"));
        assertTrue(result.url().contains("code_challenge_method=S256"));
        assertEquals("cookie", result.browserCookie());
    }
}
