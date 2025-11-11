package com.evoke.auth.security;

import com.evoke.auth.entity.Role;
import com.evoke.auth.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtProviderTest {
    
    private JwtProvider jwtProvider;
    private User user;
    
    @BeforeEach
    void setUp() {
        jwtProvider = new JwtProvider("test_secret_key_that_is_at_least_32_characters_long", 900000L);
        
        Role userRole = new Role("ROLE_USER");
        userRole.setId(1L);
        
        user = new User("testuser", "test@example.com", "password");
        user.setId(1L);
        user.setRoles(Set.of(userRole));
    }
    
    @Test
    void generateAccessToken_Success() {
        // When
        String token = jwtProvider.generateAccessToken(user);
        
        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }
    
    @Test
    void getUsernameFromToken_Success() {
        // Given
        String token = jwtProvider.generateAccessToken(user);
        
        // When
        String username = jwtProvider.getUsernameFromToken(token);
        
        // Then
        assertEquals("testuser", username);
    }
    
    @Test
    void getUserIdFromToken_Success() {
        // Given
        String token = jwtProvider.generateAccessToken(user);
        
        // When
        Long userId = jwtProvider.getUserIdFromToken(token);
        
        // Then
        assertEquals(1L, userId);
    }
    
    @Test
    void validateToken_ValidToken_ReturnsTrue() {
        // Given
        String token = jwtProvider.generateAccessToken(user);
        
        // When
        boolean isValid = jwtProvider.validateToken(token);
        
        // Then
        assertTrue(isValid);
    }
    
    @Test
    void validateToken_InvalidToken_ReturnsFalse() {
        // Given
        String invalidToken = "invalid.jwt.token";
        
        // When
        boolean isValid = jwtProvider.validateToken(invalidToken);
        
        // Then
        assertFalse(isValid);
    }
    
    @Test
    void validateToken_ExpiredToken_ReturnsFalse() {
        // Given - Create a provider with very short expiration
        JwtProvider shortExpirationProvider = new JwtProvider(
            "test_secret_key_that_is_at_least_32_characters_long", 1L);
        String token = shortExpirationProvider.generateAccessToken(user);
        
        // Wait for token to expire
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // When
        boolean isValid = jwtProvider.validateToken(token);
        
        // Then
        assertFalse(isValid);
    }
    
    @Test
    void getExpirationFromToken_Success() {
        // Given
        String token = jwtProvider.generateAccessToken(user);
        
        // When
        var expiration = jwtProvider.getExpirationFromToken(token);
        
        // Then
        assertNotNull(expiration);
        assertTrue(expiration.getTime() > System.currentTimeMillis());
    }
    
    @Test
    void getExpirationMs_ReturnsCorrectValue() {
        // When
        Long expirationMs = jwtProvider.getExpirationMs();
        
        // Then
        assertEquals(900000L, expirationMs);
    }
}