package com.evoke.auth.security;

import com.evoke.auth.Constants;
import com.evoke.auth.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtProvider {
    
    private final SecretKey key;
    private final Long expirationMs;
    
    public JwtProvider(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.expiration-ms}") Long expirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }
    
    public String generateAccessToken(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);
        
        String authorities = user.getRoles().stream()
            .map(role -> role.getName())
            .collect(Collectors.joining(","));
        
        return Jwts.builder()
            .setSubject(user.getUsername())
            .claim(Constants.JWT_CLAIM_USERNAME, user.getUsername())
            .claim(Constants.JWT_CLAIM_USER_ID, user.getId())
            .claim(Constants.JWT_CLAIM_AUTHORITIES, authorities)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(key)
            .compact();
    }
    
    public String getUsernameFromToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
        
        return claims.getSubject();
    }
    
    public Long getUserIdFromToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
        
        return claims.get(Constants.JWT_CLAIM_USER_ID, Long.class);
    }
    
    public String getAuthoritiesFromToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
        
        return claims.get(Constants.JWT_CLAIM_AUTHORITIES, String.class);
    }
    
    public boolean validateToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        try {
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.debug("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.debug("JWT token is malformed: {}", e.getMessage());
        } catch (SecurityException e) {
            log.debug("JWT signature validation failed: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.debug("JWT token compact of handler are invalid: {}", e.getMessage());
        }
        return false;
    }
    
    public Date getExpirationFromToken(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        
        Claims claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
        
        return claims.getExpiration();
    }
    
    public Long getExpirationMs() {
        return expirationMs;
    }
}