package com.linkmoa.common.exception;

public class SecurityException extends BusinessException {

    public SecurityException(ErrorCode errorCode) {
        super(errorCode);
    }

    public SecurityException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
