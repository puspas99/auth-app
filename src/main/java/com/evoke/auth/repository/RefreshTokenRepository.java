package com.evoke.auth.repository;

import com.evoke.auth.entity.RefreshToken;
import com.evoke.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByToken(String token);
    
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = ?1 AND rt.revoked = false AND rt.expiryDate > ?2")
    Optional<RefreshToken> findValidTokenByToken(String token, Instant now);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user = ?1")
    void deleteByUser(User user);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < ?1 OR rt.revoked = true")
    void deleteExpiredAndRevokedTokens(Instant now);
    
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = ?1")
    void revokeAllByUser(User user);
    
    boolean existsByTokenAndRevokedFalse(String token);
}