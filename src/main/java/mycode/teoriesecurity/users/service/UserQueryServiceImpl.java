package mycode.teoriesecurity.users.service;

import lombok.AllArgsConstructor;
import mycode.teoriesecurity.users.dtos.UserResponse;
import mycode.teoriesecurity.users.exceptions.NoUserFound;
import mycode.teoriesecurity.users.repository.UserRepository;
import org.springframework.stereotype.Service;
import mycode.teoriesecurity.users.model.User;

@Service
@AllArgsConstructor
public class UserQueryServiceImpl implements UserQueryService{

    UserRepository userRepository;
    @Override
    public User findByEmail(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new NoUserFound("No user with this email found"));



        return user;
    }
}
