package com.linkmoa.common.exception;

import static org.springframework.http.HttpStatus.*;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    EXPIRED_TOKEN_EXCEPTION(UNAUTHORIZED, "토큰이 만료되었습니다."),
    INVALID_TOKEN_EXCEPTION(UNAUTHORIZED, "유효하지 않은 토큰입니다.");

    private final HttpStatus status;
    private final String message;
}
