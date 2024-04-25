package com.backend.security.service;

import com.backend.security.dto.AuthRequest;
import com.backend.security.dto.AuthResponse;
import com.backend.security.model.CustomUserDetails;
import com.backend.security.model.User;
import com.backend.security.model.UserRole;
import com.backend.security.repo.UserRepository;
import com.backend.security.repo.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class IdentityService {
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    public AuthResponse registerUser(AuthRequest request) {

        Optional<User> existingUser = userRepository.getByUsername(request.getUsername());

        if (existingUser.isPresent()) {
            throw new RuntimeException(request.getUsername());
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(List.of(userRoleRepository.getRoleUser()))
                .build();
        userRepository.save(user);
        return login(request);
    }

    public AuthResponse login(AuthRequest authRequest) {

        User user = authenticate(authRequest.getUsername(), authRequest.getPassword());

        return new AuthResponse(user.getId(), user.getUsername(),
                jwtService.generateToken(new CustomUserDetails(user)),
                jwtService.generateRefreshToken(new CustomUserDetails(user)),
                user.getRoles());
    }

    public AuthResponse logout(String token) {
        return new AuthResponse(
                Long.parseLong(jwtService.extractUserId(token)),
                jwtService.extractUsername(token),
                jwtService.generateLogoutToken(token),
                null,
                Collections.emptyList());
    }

    public AuthResponse refreshToken(String refreshToken) {

        if (!jwtService.extractExpiration(refreshToken).before(new Date())) {

            String userId = jwtService.extractUserId(refreshToken);
            Optional<User> userOpt = userRepository.findById(Long.parseLong(userId));

            if (userOpt.isPresent()) {
                return new AuthResponse(userOpt.get().getId(), userOpt.get().getUsername(),
                        jwtService.generateToken(new CustomUserDetails(userOpt.get())),
                        jwtService.generateRefreshToken(new CustomUserDetails(userOpt.get())),
                        userOpt.get().getRoles());
            }
        }

        throw new RuntimeException("(Token is not valid)");
    }

    private User authenticate(String username, String password) {

        try {
            log.info("Authenticating user by username: {}", username);

            Optional<User> userOpt = userRepository.getByUsername(username);
            if (userOpt.isPresent())
                if (passwordEncoder.matches(password, userOpt.get().getPassword()))
                    return userOpt.get();

        } catch (Exception e) {
            //ignore
        }

        throw new RuntimeException("(Invalid Username or password!)");
    }

}
