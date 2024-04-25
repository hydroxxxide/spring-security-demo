package com.backend.security.dto;

import com.backend.security.model.UserRole;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class AuthResponse {

    public AuthResponse(long userId, String username, String accessToken, String refreshToken, List<UserRole> roles) {
        this.userId = userId;
        this.username = username;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.roles = roles;
    }

    private long userId;

    private String username;

    private String accessToken;

    private String refreshToken;

    private List<UserRole> roles;

    private String tokenType = "Bearer";
}
