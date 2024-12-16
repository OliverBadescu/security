package mycode.teoriesecurity.users.service;


import lombok.AllArgsConstructor;
import mycode.teoriesecurity.system.security.UserRole;
import mycode.teoriesecurity.users.dtos.CreateUserDTO;
import mycode.teoriesecurity.users.exceptions.UserAlreadyExists;
import mycode.teoriesecurity.users.model.User;
import mycode.teoriesecurity.users.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@AllArgsConstructor
public class UserCommandServiceImpl implements UserCommandService{
    private BCryptPasswordEncoder passwordEncoder;
    UserRepository userRepository;


    @Override
    public void addUser(CreateUserDTO createUserDTO) {
        User user  = User.builder()
                .phoneNumber(createUserDTO.phoneNumber())
                .password(passwordEncoder.encode(createUserDTO.password()))
                .firstName(createUserDTO.firstName())
                .lastName(createUserDTO.lastName())
                .email(createUserDTO.email())
                .createdAt(LocalDateTime.now())
                .registeredAt(LocalDateTime.now())
                .active(true)
                .userRole(UserRole.CLIENT)
                .build();

        List<User> list = userRepository.findAll();

        list.forEach( user1 -> {
            if(user.getEmail().equals(user1.getEmail())){
                throw new UserAlreadyExists("User with this email already exists");
            }
        });

        userRepository.saveAndFlush(user);
    }
}
