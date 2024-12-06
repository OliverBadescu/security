package mycode.teoriesecurity.users.dtos;

import mycode.teoriesecurity.system.security.UserRole;

public record RegisterResponse(String jwtToken,
                               String firstName,
                               String lastName,
                               String phoneNumber,
                               String email,
                               boolean active,
                               UserRole userRole) {
}
