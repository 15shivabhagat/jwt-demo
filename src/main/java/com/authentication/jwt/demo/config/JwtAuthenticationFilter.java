package com.authentication.jwt.demo.config;

import java.io.IOException;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.authentication.jwt.demo.utils.JwtUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // Fetch token from request
        var jwtTokenOptional = getTokenFromRequest(request);

        // Validate JWT token -> JWT utils
        if(jwtTokenOptional.isPresent()) {
            var jwtToken = jwtTokenOptional.get();
            if(JwtUtils.validateToken(jwtToken)) {
                // Get Username from JWT token
                Optional<String> usernameOptional = JwtUtils.getUsernameFromToken(jwtToken);
                usernameOptional.ifPresent(username -> {
                    // Fetch User details with the help of usernmame
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // Create Authentication Token
                    var authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource()
                                        .buildDetails(request));
                
                    // Set Authentication token to Security Context
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                });    
            }
        }

        // Pass request and response to next filter
        filterChain.doFilter(request, response);
    }

    private Optional<String> getTokenFromRequest(HttpServletRequest request) {
        // Extract Authentication header
        var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Token Format -> Bearer <JWT_TOKEN>
        // need to remove Bearer from that so that we can get only <JWT_TOKEN>
        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer")) {
            return Optional.of(authHeader.substring(7));
        }
        return Optional.ofNullable(null);
    }
    
}
