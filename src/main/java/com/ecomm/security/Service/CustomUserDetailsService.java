package com.ecomm.security.Service;

import com.ecomm.security.DAO.RoleRepo;
import com.ecomm.security.DAO.UserRepo;
import com.ecomm.security.DTO.SigninRequestDto;
import com.ecomm.security.Model.Role;
import com.ecomm.security.Model.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepo userRepo;
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    public CustomUserDetailsService(UserRepo userRepo, RoleRepo roleRepo) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity user = userRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Username not found"));
        return new User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()));
    }

    private Collection<GrantedAuthority> mapRolesToAuthorities(List<Role> roles){
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }

    public UserEntity createUser(SigninRequestDto signinRequestDTO){
        UserEntity user = new UserEntity();
        user.setEmail(signinRequestDTO.getEmail());
        user.setFirstName(signinRequestDTO.getFirstname());
        user.setLastName(signinRequestDTO.getLastname());
        user.setPassword(passwordEncoder.encode(signinRequestDTO.getPassword()));
        user.setIsJWTAuthenticated(Boolean.TRUE);
        user.setUsername();
        Role roles = roleRepo.findByName("ROLE_USER").get();
        user.setRoles(Collections.singletonList(roles));
        userRepo.save(user);
        return user;
    }
}
