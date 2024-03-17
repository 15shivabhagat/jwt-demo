package com.authentication.jwt.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;



@RestController
@RequestMapping("/api/secret")
public class SecretController {
    

    @GetMapping("/")
    public ResponseEntity<String> getSecret() {
        return ResponseEntity.status(HttpStatus.OK).body("Hello you are authorezed to access secret");
    }
    
}
