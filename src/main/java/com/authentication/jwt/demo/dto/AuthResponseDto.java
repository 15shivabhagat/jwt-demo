package com.authentication.jwt.demo.dto;

public record AuthResponseDto(String token, AuthStatus authStatus) {
} 