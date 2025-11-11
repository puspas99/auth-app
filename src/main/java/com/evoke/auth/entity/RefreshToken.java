package com.evoke.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class RefreshToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @Column(name = "token", nullable = false, unique = true)
    @NotBlank(message = "Token is required")
    private String token;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @NotNull(message = "User is required")
    private User user;
    
    @Column(name = "expiry_date", nullable = false)
    @NotNull(message = "Expiry date is required")
    private Instant expiryDate;
    
    @Column(name = "revoked", nullable = false)
    private Boolean revoked = false;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    public RefreshToken(String token, User user, Instant expiryDate) {
        this.token = Objects.requireNonNull(token, "Token cannot be null");
        this.user = Objects.requireNonNull(user, "User cannot be null");
        this.expiryDate = Objects.requireNonNull(expiryDate, "Expiry date cannot be null");
        this.revoked = false;
    }
    
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }
    
    public boolean isRevoked() {
        return this.revoked != null ? this.revoked : false;
    }
    
    public void revoke() {
        this.revoked = true;
    }
}