package com.evoke.auth.repository;

import com.evoke.auth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsernameIgnoreCase(String username);
    
    Optional<User> findByEmailIgnoreCase(String email);
    
    boolean existsByUsernameIgnoreCase(String username);
    
    boolean existsByEmailIgnoreCase(String email);
    
    @Query("SELECT u FROM User u WHERE u.active = true")
    Page<User> findAllActiveUsers(Pageable pageable);
    
    @Query("SELECT u FROM User u JOIN FETCH u.roles WHERE u.username = ?1")
    Optional<User> findByUsernameWithRoles(String username);
}