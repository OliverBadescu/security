package mycode.teoriesecurity.utils;

import org.springframework.http.HttpStatus;

import java.util.Date;

public record HttpResponse(Date timeStamp, int httpStatusCode, HttpStatus httpStatus, String reason, String message) {
}