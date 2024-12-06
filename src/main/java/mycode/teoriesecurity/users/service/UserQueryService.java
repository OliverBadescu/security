package mycode.teoriesecurity.users.service;

import mycode.teoriesecurity.users.dtos.UserResponse;
import mycode.teoriesecurity.users.model.User;

public interface UserQueryService {

    User findByEmail(String email);
}
