package com.evoke.auth.service;

import com.evoke.auth.entity.User;
import com.evoke.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserService {
    
    private final UserRepository userRepository;
    
    public Optional<User> findByUsername(String username) {
        Objects.requireNonNull(username, "Username cannot be null");
        return userRepository.findByUsernameIgnoreCase(username.trim());
    }
    
    public Optional<User> findByEmail(String email) {
        Objects.requireNonNull(email, "Email cannot be null");
        return userRepository.findByEmailIgnoreCase(email.trim());
    }
    
    public Optional<User> findById(Long id) {
        Objects.requireNonNull(id, "ID cannot be null");
        return userRepository.findById(id);
    }
    
    public Optional<User> findByUsernameWithRoles(String username) {
        Objects.requireNonNull(username, "Username cannot be null");
        return userRepository.findByUsernameWithRoles(username.trim());
    }
    
    public boolean existsByUsername(String username) {
        Objects.requireNonNull(username, "Username cannot be null");
        return userRepository.existsByUsernameIgnoreCase(username.trim());
    }
    
    public boolean existsByEmail(String email) {
        Objects.requireNonNull(email, "Email cannot be null");
        return userRepository.existsByEmailIgnoreCase(email.trim());
    }
    
    @Transactional
    public User save(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        log.debug("Saving user with username: {}", user.getUsername());
        return userRepository.save(user);
    }
    
    public Page<User> findAllActiveUsers(Pageable pageable) {
        Objects.requireNonNull(pageable, "Pageable cannot be null");
        return userRepository.findAllActiveUsers(pageable);
    }
    
    public Page<User> findAll(Pageable pageable) {
        Objects.requireNonNull(pageable, "Pageable cannot be null");
        return userRepository.findAll(pageable);
    }
    
    @Transactional
    public void deactivateUser(Long userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        user.setActive(false);
        userRepository.save(user);
        log.info("User deactivated: {}", user.getUsername());
    }
    
    @Transactional
    public void activateUser(Long userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        user.setActive(true);
        userRepository.save(user);
        log.info("User activated: {}", user.getUsername());
    }
}