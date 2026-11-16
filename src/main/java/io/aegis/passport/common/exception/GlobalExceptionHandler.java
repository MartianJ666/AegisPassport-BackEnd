package io.aegis.passport.common.exception;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.util.RequestTrace;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.util.HashMap; import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus; import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler; import org.springframework.web.bind.annotation.RestControllerAdvice;
@Slf4j @RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(org.springframework.web.multipart.MaxUploadSizeExceededException.class)
    public ResponseEntity<ApiResult<Void>> handleUploadSize(Exception ex) {
        return ResponseEntity.status(413).body(ApiResult.error(413, "上传文件超过大小限制"));
    }
    @ExceptionHandler({org.springframework.web.multipart.MultipartException.class,
            org.springframework.web.multipart.support.MissingServletRequestPartException.class})
    public ResponseEntity<ApiResult<Void>> handleMultipart(Exception ex) {
        return ResponseEntity.badRequest().body(ApiResult.error(400, "上传请求缺少文件或表单格式不正确"));
    }
    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResult<Void>> handleJson(Exception ex) {
        return ResponseEntity.badRequest().body(ApiResult.error(400, "请求数据格式不正确"));
    }
    @ExceptionHandler(org.springframework.web.HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResult<Void>> handleMediaType(Exception ex) {
        return ResponseEntity.status(415).body(ApiResult.error(415, "不支持的请求类型，请使用 multipart 表单及 JSON 数据"));
    }
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResult<Void>> handleBusiness(BusinessException ex, HttpServletRequest req) {
        ErrorCode ec = ex.getErrorCode();
        String traceId = RequestTrace.current();
        log.warn("[{}] Business: code={} msg={}", traceId, ec.getCode(), ec.getMessage());
        return ResponseEntity.status(ec.getStatus())
                .body(ApiResult.<Void>builder().code(ec.getStatus()).errorCode(ec.getCode()).message(ex.getMessage()).traceId(traceId).build());
    }
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResult<Void>> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiResult.error(403, "权限不足"));
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResult<Map<String, String>>> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> errors.put(((FieldError) error).getField(), error.getDefaultMessage()));
        return ResponseEntity.badRequest().body(ApiResult.<Map<String, String>>builder().code(400).message("参数校验失败").data(errors).build());
    }
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResult<Void>> handleConstraint(ConstraintViolationException ex) {
        return ResponseEntity.badRequest().body(ApiResult.error(400, "参数校验失败：" + ex.getMessage()));
    }
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResult<Void>> handleIllegal(IllegalArgumentException ex, HttpServletRequest req) {
        return ResponseEntity.badRequest().body(ApiResult.error(400, ex.getMessage()));
    }
    @ExceptionHandler(org.springframework.web.HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResult<Void>> handleMethod(org.springframework.web.HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(405).allow(ex.getSupportedHttpMethods()==null?new org.springframework.http.HttpMethod[0]:ex.getSupportedHttpMethods().toArray(new org.springframework.http.HttpMethod[0])).body(ApiResult.error(405,"不支持的请求方法"));
    }
    @ExceptionHandler({org.springframework.web.bind.MissingServletRequestParameterException.class,org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ApiResult<Void>> handleParameter(Exception ex) {
        return ResponseEntity.badRequest().body(ApiResult.error(400,"请求参数缺失或格式不正确"));
    }
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResult<Void>> handleNoResource(NoResourceFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiResult.error(404, "资源不存在"));
    }
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResult<Void>> handleRuntime(RuntimeException ex, HttpServletRequest req) {
        String traceId = RequestTrace.current();
        log.error("[{}] Runtime: {}", traceId, ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResult.<Void>builder()
                .code(500).errorCode("INTERNAL_ERROR").message("服务器暂时不可用，请稍后重试")
                .traceId(traceId).build());
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResult<Void>> handleAll(Exception ex, HttpServletRequest req) {
        String traceId = RequestTrace.current();
        log.error("[{}] Unhandled: {}", traceId, ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResult.<Void>builder()
                .code(500).errorCode("INTERNAL_ERROR").message("系统暂时不可用，请稍后重试")
                .traceId(traceId).build());
    }
}
