package com.ecomm.security.DTO;

import lombok.Data;

@Data
public class SigninRequestDto {
    private String firstname;
    private String lastname;
    private String email;
    private String password;
}
