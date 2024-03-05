package com.ecomm.security.security;

import com.ecomm.security.Model.UniqueToken;
import com.ecomm.security.Service.CustomUserDetailsService;
import com.ecomm.security.Service.UniqueTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JWTGenerator tokenGenerator;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Autowired
    private UniqueTokenService uniqueTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String tokenType = getTokenTypeFromRequest(request);
        String token = getTokenFromRequest(request);
        if (tokenType.equals("Generate")){
            if(StringUtils.hasText(token) && tokenGenerator.validateToken(token)){
                String email = tokenGenerator.getEmailFromJWT(token);
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                System.out.println(authenticationToken);
            }
        }
        else if(tokenType.equals("Refresh")){
            if (StringUtils.hasText(token)) {
                String email = uniqueTokenService.getEmailFromToken(token);
                if(!uniqueTokenService.isUniqueTokenExpired(email)){
                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }
        filterChain.doFilter(request, response);
    }



    private String getTokenFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7,bearerToken.length());
        }
    return null;
    }

    private String getTokenTypeFromRequest(HttpServletRequest request){
        String tokenType = request.getHeader("Token-Type");
        if(StringUtils.hasText(tokenType)){
            return tokenType;
        }
        return null;
    }


}
