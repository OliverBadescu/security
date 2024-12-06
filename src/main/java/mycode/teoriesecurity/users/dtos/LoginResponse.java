package mycode.teoriesecurity.users.dtos;

import mycode.teoriesecurity.system.security.UserRole;

public record LoginResponse(String jwtToken,
                            String firstName,
                            String lastName,
                            String phoneNumber,
                            String email,
                            boolean active,
                            UserRole userRole) {
}
