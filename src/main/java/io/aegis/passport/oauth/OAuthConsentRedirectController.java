package io.aegis.passport.oauth;

import io.aegis.passport.config.PassportProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Intercepts the SAS consent-page redirect ({@code GET /oauth2/consent?params})
 * and forwards it to the Vue SPA's consent page, preserving the query string.
 */
@Controller
@RequiredArgsConstructor
public class OAuthConsentRedirectController {

    private final PassportProperties props;

    @GetMapping("/oauth2/consent")
    public void redirect(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String query = request.getQueryString();
        String dest = props.getConsent().getBaseUrl() + "/oauth2/consent"
                + (query != null ? "?" + query : "");
        response.sendRedirect(dest);
    }
}
