package io.aegis.passport.common.exception;

import lombok.Getter;

/**
 * Thrown by service code for expected, client-actionable failures. Carries an
 * {@link ErrorCode} so the global handler can map it to the right HTTP status
 * and a stable machine code.
 */
@Getter
public class BusinessException extends RuntimeException {

    private final ErrorCode errorCode;

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public static BusinessException of(ErrorCode errorCode) {
        return new BusinessException(errorCode);
    }

    public static BusinessException of(ErrorCode errorCode, String message) {
        return new BusinessException(errorCode, message);
    }

    public static BusinessException of(ErrorCode errorCode, String message, Throwable cause) {
        return new BusinessException(errorCode, message, cause);
    }
}
