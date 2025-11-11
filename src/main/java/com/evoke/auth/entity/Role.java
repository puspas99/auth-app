package com.evoke.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @Column(name = "name", nullable = false, unique = true, length = 50)
    @NotBlank(message = "Role name is required")
    @Size(max = 50, message = "Role name must not exceed 50 characters")
    private String name;
    
    @Column(name = "description", length = 255)
    @Size(max = 255, message = "Description must not exceed 255 characters")
    private String description;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    public Role(String name) {
        this.name = Objects.requireNonNull(name, "Role name cannot be null");
    }
    
    public Role(String name, String description) {
        this.name = Objects.requireNonNull(name, "Role name cannot be null");
        this.description = description;
    }
}