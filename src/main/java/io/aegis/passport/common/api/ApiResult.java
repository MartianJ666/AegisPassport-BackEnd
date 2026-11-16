package io.aegis.passport.common.api;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor; import lombok.Builder; import lombok.Data; import lombok.NoArgsConstructor;
@Data @Builder @NoArgsConstructor @AllArgsConstructor @JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResult<T> {
    private Integer code; private String message; private String errorCode; private T data; private String traceId;
    public static <T> ApiResult<T> ok(T data) { return ApiResult.<T>builder().code(200).message("OK").data(data).build(); }
    public static <T> ApiResult<T> ok() { return ApiResult.<T>builder().code(200).message("OK").build(); }
    public static <T> ApiResult<T> error(Integer code, String message) { return ApiResult.<T>builder().code(code).message(message).build(); }
    public static <T> ApiResult<T> error(Integer code, String errorCode, String message) { return ApiResult.<T>builder().code(code).errorCode(errorCode).message(message).build(); }
}
