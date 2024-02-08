package com.ecomm.security.DTO;

import lombok.Builder;
import lombok.Data;
@Builder
@Data
public class RefreshTokenResponseDto {
    public String jwtToken;
    public String uniqueToken;
}
