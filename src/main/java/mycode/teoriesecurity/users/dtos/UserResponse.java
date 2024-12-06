package mycode.teoriesecurity.users.dtos;

import lombok.Builder;


@Builder
public record UserResponse(long id,String email, String password, String firstName, String lastName, String phone) {
}
