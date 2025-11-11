package com.evoke.auth.security;

import com.evoke.auth.entity.User;
import com.evoke.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserService userService;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Objects.requireNonNull(username, "Username cannot be null");
        
        User user = userService.findByUsernameWithRoles(username.trim())
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        return new CustomUserDetails(user);
    }
}