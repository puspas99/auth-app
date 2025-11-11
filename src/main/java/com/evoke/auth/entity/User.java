package com.evoke.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @Column(name = "username", nullable = false, unique = true, length = 50)
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Column(name = "email", nullable = false, unique = true, length = 100)
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    private String email;
    
    @Column(name = "password", nullable = false)
    @NotBlank(message = "Password is required")
    @JsonIgnore
    private String password;
    
    @Column(name = "active", nullable = false)
    private Boolean active = true;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    public User(String username, String email, String password) {
        this.username = Objects.requireNonNull(username, "Username cannot be null");
        this.email = Objects.requireNonNull(email, "Email cannot be null");
        this.password = Objects.requireNonNull(password, "Password cannot be null");
        this.active = true;
        this.roles = new HashSet<>();
    }
    
    public void addRole(Role role) {
        Objects.requireNonNull(role, "Role cannot be null");
        this.roles.add(role);
    }
    
    public void removeRole(Role role) {
        Objects.requireNonNull(role, "Role cannot be null");
        this.roles.remove(role);
    }
    
    public Set<Role> getRoles() {
        return new HashSet<>(this.roles);
    }
    
    public void setRoles(Set<Role> roles) {
        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
    }
    
    public Boolean isActive() {
        return this.active != null ? this.active : false;
    }
}