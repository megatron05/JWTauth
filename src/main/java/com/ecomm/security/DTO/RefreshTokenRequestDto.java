package com.ecomm.security.DTO;

import lombok.Data;

@Data
public class RefreshTokenRequestDto {
    //delete this dto!!!!
    public String jwtToken;
    public String uniqueToken;
}
