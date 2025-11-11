package com.evoke.auth.controller;

import com.evoke.auth.dto.requests.LoginRequest;
import com.evoke.auth.dto.requests.RefreshRequest;
import com.evoke.auth.dto.requests.RegisterRequest;
import com.evoke.auth.dto.responses.ApiResponse;
import com.evoke.auth.dto.responses.TokenResponse;
import com.evoke.auth.entity.User;
import com.evoke.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {
    
    private final AuthService authService;
    
    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            User user = authService.register(request);
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("id", user.getId());
            responseData.put("username", user.getUsername());
            responseData.put("email", user.getEmail());
            responseData.put("active", user.isActive());
            responseData.put("createdAt", user.getCreatedAt());
            
            return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User registered successfully", responseData));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Registration error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Internal server error"));
        }
    }
    
    @PostMapping("/login")
    @Operation(summary = "Authenticate user and return JWT tokens")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenResponse tokenResponse = authService.login(request);
            return ResponseEntity.ok(ApiResponse.success("Login successful", tokenResponse));
        } catch (Exception e) {
            log.warn("Login failed for user: {}", request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error("Invalid credentials"));
        }
    }
    
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<ApiResponse<TokenResponse>> refreshToken(@Valid @RequestBody RefreshRequest request) {
        try {
            TokenResponse tokenResponse = authService.refreshToken(request.getRefreshToken());
            return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", tokenResponse));
        } catch (Exception e) {
            log.warn("Token refresh failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error("Invalid or expired refresh token"));
        }
    }
    
    @PostMapping("/logout")
    @Operation(summary = "Logout user and revoke refresh token")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody RefreshRequest request) {
        try {
            authService.logout(request.getRefreshToken());
            return ResponseEntity.ok(ApiResponse.success("Logout successful"));
        } catch (Exception e) {
            log.warn("Logout failed", e);
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Logout failed"));
        }
    }
}