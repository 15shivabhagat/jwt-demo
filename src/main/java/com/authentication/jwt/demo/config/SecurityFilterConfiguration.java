package com.authentication.jwt.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityFilterConfiguration {

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired    
    public SecurityFilterConfiguration(AuthenticationEntryPoint authenticationEntryPoint, 
    JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        //Disable cors
        httpSecurity.cors(corsConfig -> corsConfig.disable());

        // Disable csrf
        httpSecurity.csrf(csrfConfig -> csrfConfig.disable());

        // Http Request Filter
        httpSecurity.authorizeHttpRequests(
            requestMatcher ->  
                requestMatcher.requestMatchers("/api/auth/login/**").permitAll()
                            .requestMatchers("/api/auth/sign-up/**").permitAll()
                            .anyRequest().authenticated()
        );
 
        // Exception Handler
        // Authentication Entry Point -> Exception Handler
        httpSecurity.exceptionHandling(
            exceptionConfig -> exceptionConfig.authenticationEntryPoint(authenticationEntryPoint)
        );

        // Set Session policy = STATELESS
        httpSecurity.sessionManagement(
            sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // Add JWT Authenticaton Filter
        httpSecurity.addFilterBefore(
            jwtAuthenticationFilter, 
            UsernamePasswordAuthenticationFilter.class
        );
        return httpSecurity.build();
    }
}
