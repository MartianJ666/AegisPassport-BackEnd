package io.aegis.passport.security;

import io.aegis.passport.common.api.ApiResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

/** Exposes the RSA public key for password transport encryption by the SPA. */
@RestController
@RequestMapping("/api/rsa")
public class RsaController {

    private final RsaTransportService rsa;

    public RsaController(RsaTransportService rsa) {
        this.rsa = rsa;
    }

    @GetMapping("/public-key")
    public ResponseEntity<ApiResult<Map<String, String>>> publicKey() {
        return ResponseEntity.ok(ApiResult.ok(Map.of("publicKey", rsa.getPublicKeyBase64())));
    }
}
