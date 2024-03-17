package com.authentication.jwt.demo.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authentication.jwt.demo.model.AppUser;
import com.authentication.jwt.demo.repository.AppUserRepo;
import com.authentication.jwt.demo.utils.JwtUtils;

import lombok.RequiredArgsConstructor;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final AppUserRepo appUserRepo;

    @Override
    public String login(String username, String password) {
        var authToken = new UsernamePasswordAuthenticationToken(username, password);

        var authenticate = authenticationManager.authenticate(authToken);

        return JwtUtils.generateToken(((UserDetails)(authenticate.getPrincipal())).getUsername());
  
    }

    @Override
    public String signUp(String name, String username, String password) {
        // Check whether user exists or not
        if(appUserRepo.existsByUsername(username)){
            throw new RuntimeException("User already exist");
        }
        // Encode the password
        String encodedPassword = passwordEncoder.encode(password);
        
        // Authorities
        ArrayList<GrantedAuthority> authorities =new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        // Create App User
        AppUser user = AppUser.builder()
            .name(name)
            .username(username)
            .password(encodedPassword)
            .authorities(authorities)
            .build();
        
        // Save User
        appUserRepo.save(user);

        // Generate token
        return JwtUtils.generateToken(username);
    }
    
}
