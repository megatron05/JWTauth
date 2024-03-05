package com.ecomm.security.Service;

import com.ecomm.security.security.JWTGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class AuthService {


    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UniqueTokenService tokenService;
    public Authentication authenticateUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        password));
        if (authentication.isAuthenticated()) {
            tokenService.findUniqueToken(email);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return authentication;
        } else
            throw new UsernameNotFoundException("invalid user request !");
    }

}