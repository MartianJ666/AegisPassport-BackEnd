package io.aegis.passport.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import io.aegis.passport.common.exception.GlobalExceptionHandler;
class SecurityResponseTests {
 @Test void unsupportedMethodIs405WithAllowHeader(){var r=new GlobalExceptionHandler().handleMethod(new org.springframework.web.HttpRequestMethodNotSupportedException("GET",java.util.List.of("POST")));assertEquals(405,r.getStatusCode().value());assertTrue(r.getHeaders().getAllow().contains(org.springframework.http.HttpMethod.POST));}
 @Test void missingParameterIs400(){assertEquals(400,new GlobalExceptionHandler().handleParameter(new Exception()).getStatusCode().value());}
}
