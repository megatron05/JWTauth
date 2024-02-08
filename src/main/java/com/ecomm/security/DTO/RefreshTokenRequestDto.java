package com.ecomm.security.DTO;

import lombok.Data;

@Data
public class RefreshTokenRequestDto {
    public String jwtToken;
    public String uniqueToken;
}
