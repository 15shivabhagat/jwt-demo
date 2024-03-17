package com.authentication.jwt.demo.service;

public interface AuthService {
    public String login(String username, String password);

    public String signUp(String name, String username, String password);
}
