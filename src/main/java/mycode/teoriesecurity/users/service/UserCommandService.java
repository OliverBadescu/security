package mycode.teoriesecurity.users.service;

import mycode.teoriesecurity.users.dtos.CreateUserDTO;

public interface UserCommandService{

    void addUser(CreateUserDTO createUserDTO);
}
