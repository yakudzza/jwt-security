package com.example.task4.dto;



public class AuthRequest {
    private String username;
    private String password;

    public AuthRequest(String user, String password) {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
