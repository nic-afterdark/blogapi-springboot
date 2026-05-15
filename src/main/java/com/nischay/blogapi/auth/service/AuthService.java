package com.nischay.blogapi.auth.service;

import com.nischay.blogapi.auth.dto.AuthResponse;
import com.nischay.blogapi.auth.dto.LoginRequest;
import com.nischay.blogapi.auth.dto.RegisterRequest;
import com.nischay.blogapi.user.entity.User;
import com.nischay.blogapi.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private  final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    public AuthResponse register(RegisterRequest request){
        // Step 1: Check for duplicates BEFORE inserting
        if(userRepository.existsByUsername(request.getUsername())){
            throw new RuntimeException("Username already exists");
        }

        if(userRepository.existsByEmail(request.getEmail())){
            throw new RuntimeException("Email already exists");
        }
        // Step 2: Hash the password — NEVER store plain text
        String hashPassword = passwordEncoder.encode(request.getPassword());
        // Step 3: Build the user entity
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(hashPassword)
                .build();
        // Step 4: Save to database
        User savedUser = userRepository.save(user);
        // Step 5: Return response (never expose password)
        return AuthResponse.builder()
                .userId(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .message("User registered successfully")
                .build();

    }
    public AuthResponse login(LoginRequest request) {
        // Step 1: Authenticate credentials via Spring Security
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // Step 2: Credentials are valid — fetch user from DB
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Step 3: Generate JWT token
        String token = jwtService.generateToken(user.getUsername());

        // Step 4: Build and return response
        return AuthResponse.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .token(token)
                .message("Login successful")
                .build();
    }

}
