package com.evoke.auth.service;

import com.evoke.auth.entity.RefreshToken;
import com.evoke.auth.entity.User;
import com.evoke.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RefreshTokenService {
    
    private final RefreshTokenRepository refreshTokenRepository;
    
    @Value("${jwt.refresh-expiration-ms}")
    private Long refreshExpirationMs;
    
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        
        // Revoke existing tokens for the user (optional, for single device login)
        // revokeAllUserTokens(user);
        
        String token = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plusMillis(refreshExpirationMs);
        
        RefreshToken refreshToken = new RefreshToken(token, user, expiryDate);
        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        
        log.debug("Created refresh token for user: {}", user.getUsername());
        return savedToken;
    }
    
    public RefreshToken verifyExpiration(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
            .orElseThrow(() -> new RuntimeException("Refresh token not found"));
        
        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token is revoked");
        }
        
        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token is expired");
        }
        
        return refreshToken;
    }
    
    @Transactional
    public void revokeToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        refreshTokenRepository.findByToken(token)
            .ifPresent(refreshToken -> {
                refreshToken.revoke();
                refreshTokenRepository.save(refreshToken);
                log.debug("Refresh token revoked");
            });
    }
    
    @Transactional
    public void revokeAllUserTokens(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        
        refreshTokenRepository.revokeAllByUser(user);
        log.debug("All refresh tokens revoked for user: {}", user.getUsername());
    }
    
    @Transactional
    public void deleteByUser(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        
        refreshTokenRepository.deleteByUser(user);
        log.debug("All refresh tokens deleted for user: {}", user.getUsername());
    }
    
    public boolean isValidToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        try {
            verifyExpiration(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    // Cleanup expired and revoked tokens - runs every hour
    @Scheduled(fixedRate = 3600000) // 1 hour
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        refreshTokenRepository.deleteExpiredAndRevokedTokens(now);
        log.debug("Cleaned up expired and revoked refresh tokens");
    }
}