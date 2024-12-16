package mycode.teoriesecurity.users.web;


import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mycode.teoriesecurity.system.jwt.JWTTokenProvider;
import mycode.teoriesecurity.users.dtos.CreateUserDTO;
import mycode.teoriesecurity.users.dtos.LoginRequest;
import mycode.teoriesecurity.users.dtos.LoginResponse;
import mycode.teoriesecurity.users.dtos.RegisterResponse;
import mycode.teoriesecurity.users.model.User;
import mycode.teoriesecurity.users.service.UserCommandService;
import mycode.teoriesecurity.users.service.UserQueryService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import static mycode.teoriesecurity.system.Constants.JWT_TOKEN_HEADER;

@RestController
@CrossOrigin
@RequestMapping("/server/api/")
@AllArgsConstructor
@Slf4j
public class UserControllerServer {

    private final UserCommandService userCommandService;
    private final UserQueryService userQueryService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;



    @GetMapping("/findId")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
    public ResponseEntity<Long> findId(@RequestHeader("Authorization") String token){

        try {
            String tokenValue = extractToken(token);
            String username = jwtTokenProvider.getSubject(tokenValue);
            if (jwtTokenProvider.isTokenValid(username, tokenValue)) {
                User loginUser = userQueryService.findByEmail(username);
                return ResponseEntity.ok(loginUser.getId());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping("/getUserRole")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
    public ResponseEntity<String> getUserRole(@RequestHeader("Authorization") String token) {
        log.info("Role user request");
        try {
            String tokenValue = extractToken(token);
            String username = jwtTokenProvider.getSubject(tokenValue);
            if (jwtTokenProvider.isTokenValid(username, tokenValue)) {
                User loginUser = userQueryService.findByEmail(username);
                return ResponseEntity.ok(loginUser.getUserRole().toString());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while verifying token");
        }
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Test");
    }

    public String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        } else {
            throw new IllegalArgumentException("Invalid Authorization header");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest user) {

        authenticate(user.email(), user.password());
        User loginUser = userQueryService.findByEmail(user.email());
        User userPrincipal = getUser(loginUser);

        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        LoginResponse loginResponse = new LoginResponse(
                jwtHeader.getFirst(JWT_TOKEN_HEADER),
                userPrincipal.getFirstName(),
                userPrincipal.getLastName(),
                userPrincipal.getPhoneNumber(),
                userPrincipal.getEmail(),
                userPrincipal.isActive(),
                userPrincipal.getUserRole()
        );
        return new ResponseEntity<>(loginResponse, jwtHeader, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody CreateUserDTO createUserDTO){

        this.userCommandService.addUser(createUserDTO);
        User userPrincipal = userQueryService.findByEmail(createUserDTO.email());
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        RegisterResponse registerResponse = new RegisterResponse(
                jwtHeader.getFirst(JWT_TOKEN_HEADER),
                userPrincipal.getFirstName(),
                userPrincipal.getLastName(),
                userPrincipal.getPhoneNumber(),
                userPrincipal.getEmail(),
                userPrincipal.isActive(),
                userPrincipal.getUserRole()
        );
        return new ResponseEntity<>(registerResponse, jwtHeader, HttpStatus.CREATED);


    }

    private HttpHeaders getJwtHeader(User user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJWTToken(user));
        return headers;
    }

    private User getUser(User loginUser) {
        User userPrincipal = new User();
        userPrincipal.setEmail(loginUser.getEmail());
        userPrincipal.setPassword(loginUser.getPassword());
        userPrincipal.setUserRole(loginUser.getUserRole());
        userPrincipal.setActive(loginUser.isActive());
        userPrincipal.setFirstName(loginUser.getFirstName());
        userPrincipal.setLastName(loginUser.getLastName());
        userPrincipal.setPhoneNumber(loginUser.getPhoneNumber());
        userPrincipal.setRegisteredAt(loginUser.getRegisteredAt());
        userPrincipal.setCreatedAt(loginUser.getCreatedAt());
        return userPrincipal;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
