package com.ecomm.security.DTO;

import lombok.Data;

@Data
public class GoogleDto {
    private String sub;
    private String name;
    private String given_name;
    private String family_name;
    private String picture;
    private String email;
    private String email_verified;
    private String locale;
    private String token;
}
