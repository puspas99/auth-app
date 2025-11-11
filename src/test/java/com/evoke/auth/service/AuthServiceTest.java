package com.evoke.auth.service;

import com.evoke.auth.Constants;
import com.evoke.auth.dto.requests.LoginRequest;
import com.evoke.auth.dto.requests.RegisterRequest;
import com.evoke.auth.dto.responses.TokenResponse;
import com.evoke.auth.entity.Role;
import com.evoke.auth.entity.User;
import com.evoke.auth.repository.RoleRepository;
import com.evoke.auth.security.JwtProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    
    @Mock
    private UserService userService;
    
    @Mock
    private RefreshTokenService refreshTokenService;
    
    @Mock
    private RoleRepository roleRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private AuthenticationManager authenticationManager;
    
    @Mock
    private JwtProvider jwtProvider;
    
    @Mock
    private Authentication authentication;
    
    @InjectMocks
    private AuthService authService;
    
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User user;
    private Role userRole;
    
    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest("testuser", "test@example.com", "password123");
        loginRequest = new LoginRequest("testuser", "password123");
        
        userRole = new Role(Constants.ROLE_USER);
        userRole.setId(1L);
        
        user = new User("testuser", "test@example.com", "encodedPassword");
        user.setId(1L);
        user.addRole(userRole);
    }
    
    @Test
    void register_Success() {
        // Given
        when(userService.existsByUsername(anyString())).thenReturn(false);
        when(userService.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(roleRepository.findByName(Constants.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(userService.save(any(User.class))).thenReturn(user);
        
        // When
        User result = authService.register(registerRequest);
        
        // Then
        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        assertEquals("test@example.com", result.getEmail());
        verify(userService).save(any(User.class));
    }
    
    @Test
    void register_UsernameAlreadyExists_ThrowsException() {
        // Given
        when(userService.existsByUsername(anyString())).thenReturn(true);
        
        // When & Then
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> authService.register(registerRequest));
        
        assertEquals("Username already exists: testuser", exception.getMessage());
    }
    
    @Test
    void register_EmailAlreadyExists_ThrowsException() {
        // Given
        when(userService.existsByUsername(anyString())).thenReturn(false);
        when(userService.existsByEmail(anyString())).thenReturn(true);
        
        // When & Then
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> authService.register(registerRequest));
        
        assertEquals("Email already exists: test@example.com", exception.getMessage());
    }
    
    @Test
    void login_Success() {
        // Given
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(authentication);
        when(userService.findByUsernameWithRoles(anyString())).thenReturn(Optional.of(user));
        when(jwtProvider.generateAccessToken(any(User.class))).thenReturn("accessToken");
        when(jwtProvider.getExpirationMs()).thenReturn(900000L);
        when(refreshTokenService.createRefreshToken(any(User.class)))
            .thenReturn(new com.evoke.auth.entity.RefreshToken("refreshToken", user, java.time.Instant.now()));
        
        // When
        TokenResponse result = authService.login(loginRequest);
        
        // Then
        assertNotNull(result);
        assertEquals("accessToken", result.getAccessToken());
        assertEquals("refreshToken", result.getRefreshToken());
        assertEquals("Bearer", result.getTokenType());
        assertEquals(900000L, result.getExpiresIn());
    }
    
    @Test
    void login_InvalidCredentials_ThrowsException() {
        // Given
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenThrow(new BadCredentialsException("Invalid credentials"));
        
        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, 
            () -> authService.login(loginRequest));
        
        assertEquals("Invalid credentials", exception.getMessage());
    }
    
    @Test
    void login_UserNotFound_ThrowsException() {
        // Given
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(authentication);
        when(userService.findByUsernameWithRoles(anyString())).thenReturn(Optional.empty());
        
        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, 
            () -> authService.login(loginRequest));
        
        assertEquals("Invalid credentials", exception.getMessage());
    }
    
    @Test
    void login_UserInactive_ThrowsException() {
        // Given
        user.setActive(false);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(authentication);
        when(userService.findByUsernameWithRoles(anyString())).thenReturn(Optional.of(user));
        
        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, 
            () -> authService.login(loginRequest));
        
        assertEquals("Invalid credentials", exception.getMessage());
    }
}