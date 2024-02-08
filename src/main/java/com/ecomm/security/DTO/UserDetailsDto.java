package com.ecomm.security.DTO;

import com.ecomm.security.Model.Role;
import com.ecomm.security.Model.UserEntity;
import lombok.Data;


import java.util.List;

@Data
public class UserDetailsDto {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String jwtToken;
    private String uniqueToken;
    private List<Role> roles;

    public UserDetailsDto(UserEntity user, String jwtToken, String uniqueToken){
        this.username = user.getUsername();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.email = user.getEmail();
        this.jwtToken = jwtToken;
        this.uniqueToken = uniqueToken;
        this.roles = user.getRoles();
    }
}
