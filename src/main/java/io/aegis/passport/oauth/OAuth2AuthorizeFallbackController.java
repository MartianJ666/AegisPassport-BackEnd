package io.aegis.passport.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Safety net for {@code GET /oauth2/authorize}.
 *
 * <p>Normally the authorization-server filter chain consumes every
 * {@code /oauth2/authorize} request before it reaches Spring MVC. On rare
 * occasions the {@code OAuth2AuthorizationEndpointFilter} lets a valid GET pass
 * through (transient request/parameter dispatch miss), which used to surface as
 * {@code 404 资源不存在}. This controller is reached ONLY in that fall-through
 * case — it redirects the browser to the exact same authorization URL so the
 * request re-enters the authorization-server chain and is handled correctly.
 *
 * <p>If the raw query string is missing {@code response_type} the request is
 * genuinely malformed and we answer 400 instead of looping.
 */
@Controller
public class OAuth2AuthorizeFallbackController {

    @GetMapping("/oauth2/authorize")
    public void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getQueryString();
        if (query == null || !query.contains("response_type=")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":400,\"message\":\"授权请求参数不完整\"}");
            return;
        }
        // If we already saw this fall-through once, treat it as a persistent
        // dispatch failure and stop — never loop.
        if (query.contains(MARKER)) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":503,\"message\":\"授权服务暂时不可用，请重新发起授权\"}");
            return;
        }
        // Self-retry once: same URL + marker, fresh request → SAS filter handles it.
        response.sendRedirect(request.getRequestURL() + "?" + query + (query.endsWith("&") ? "" : "&") + MARKER + "=1");
    }

    private static final String MARKER = "aegis_fallback";
}
