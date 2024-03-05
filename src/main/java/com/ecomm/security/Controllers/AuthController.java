package com.ecomm.security.Controllers;

import com.ecomm.security.DAO.RoleRepo;
import com.ecomm.security.DAO.UserRepo;
import com.ecomm.security.DTO.*;
import com.ecomm.security.Model.Role;
import com.ecomm.security.Model.UniqueToken;
import com.ecomm.security.Model.UserEntity;
import com.ecomm.security.Service.AuthService;
import com.ecomm.security.Service.CustomUserDetailsService;
import com.ecomm.security.Service.UniqueTokenService;
import com.ecomm.security.security.JWTGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import java.util.Collections;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;
    @Autowired
    private CustomUserDetailsService userService;
    @Autowired
    private UniqueTokenService tokenService;
    @Autowired
    private JWTGenerator jwtGenerator;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private  RoleRepo roleRepo;


    @PostMapping("/login")
    public ResponseEntity<UserDetailsDto> login(@RequestBody SigninRequestDto signinRequestDTO){
            String jwtToken = jwtGenerator.generateToken(authService.authenticateUser(signinRequestDTO.getEmail(), signinRequestDTO.getPassword()));
            UserEntity user = userRepo.findByEmail(signinRequestDTO.getEmail()).get();
            return new ResponseEntity<>(new UserDetailsDto(user, jwtToken, tokenService.getUniqueToken(user)), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody SigninRequestDto signinRequestDTO){
        if(userRepo.existsByEmail(signinRequestDTO.getEmail())){
            return new ResponseEntity<>(userRepo.findByEmail(signinRequestDTO.getEmail()), HttpStatus.OK);
        } else {
            UserEntity user = userService.createUser(signinRequestDTO);
            String jwtToken = jwtGenerator.generateToken(authService.authenticateUser(user.getEmail(), signinRequestDTO.getPassword()));
            String uniqueToken = tokenService.getUniqueToken(user);
            return new ResponseEntity<>(new UserDetailsDto(user, jwtToken, uniqueToken), HttpStatus.OK);
        }
    }

    @PostMapping("/refreshToken")
    public RefreshTokenResponseDto refreshToken(@RequestHeader("Authorization") String bearerToken) {
        return tokenService.findByToken(bearerToken.substring(7,bearerToken.length()))
                .map(tokenService::verifyExpiration)
                .map(UniqueToken::getUser)
                .map(user -> {
                    String jwtToken = jwtGenerator.refreshToken(user.getEmail());
                    return RefreshTokenResponseDto.builder()
                            .jwtToken(jwtToken)
                            .uniqueToken(bearerToken.substring(7,bearerToken.length()))
                            .build();
                }).orElseThrow(() -> new RuntimeException(
                        "Refresh token is not in database!"));
    }

    @GetMapping("/oauthlogin")
    public String getUserDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            String email = oauth2User.getAttribute("email");
            String firstName = oauth2User.getAttribute("given_name");
            String lastName = oauth2User.getAttribute("family_name");

            // Use email, firstName, lastName as needed
            return "Email: " + email + "\nFirst Name: " + firstName + "\nLast Name: " + lastName;
        }

        return "User details not available";
    }


    @PostMapping("/google")
    public ResponseEntity<UserDetailsDto> googlesso(@RequestBody GoogleDto googleDto){
        if(userRepo.existsByEmail(googleDto.getEmail())){
            return new ResponseEntity<>(new UserDetailsDto(userRepo.findByEmail(googleDto.getEmail()).get(), googleDto.getToken(), ""), HttpStatus.OK);
        }
        else {
            UserEntity user = new UserEntity();
            user.setEmail(googleDto.getEmail());
            user.setFirstName(googleDto.getGiven_name());
            user.setLastName(googleDto.getFamily_name());
            user.setIsJWTAuthenticated(Boolean.FALSE);
            user.setUsername();
            Role roles = roleRepo.findByName("ROLE_USER").get();
            user.setRoles(Collections.singletonList(roles));
            userRepo.save(user);

            return new ResponseEntity<>(new UserDetailsDto(user, googleDto.getToken(), ""), HttpStatus.OK);
        }
    }

}
