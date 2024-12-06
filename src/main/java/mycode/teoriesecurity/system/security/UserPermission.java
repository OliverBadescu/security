package mycode.teoriesecurity.system.security;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserPermission {
    USER_READ("user:read"),
    USER_WRITE("user:write"),
    USER_ADD("user:add"),
    USER_DELETE("user:delete"),
    USER_GET("user:get"),
    USER_UPDATE("user:update"),
    USER_UPLOAD("user:upload");
    private final String permission;


}
