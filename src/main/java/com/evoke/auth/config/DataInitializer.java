package com.evoke.auth.config;

import com.evoke.auth.Constants;
import com.evoke.auth.entity.Role;
import com.evoke.auth.entity.User;
import com.evoke.auth.repository.RoleRepository;
import com.evoke.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {
    
    private final RoleRepository roleRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${admin.password:}")
    private String adminPassword;
    
    @Bean
    public ApplicationRunner initializer() {
        return args -> {
            initializeRoles();
            initializeAdminUser();
        };
    }
    
    private void initializeRoles() {
        // Create ROLE_USER if it doesn't exist
        if (!roleRepository.existsByName(Constants.ROLE_USER)) {
            Role userRole = new Role(Constants.ROLE_USER, "Standard user role");
            roleRepository.save(userRole);
            log.info("Created role: {}", Constants.ROLE_USER);
        }
        
        // Create ROLE_ADMIN if it doesn't exist
        if (!roleRepository.existsByName(Constants.ROLE_ADMIN)) {
            Role adminRole = new Role(Constants.ROLE_ADMIN, "Administrator role with full access");
            roleRepository.save(adminRole);
            log.info("Created role: {}", Constants.ROLE_ADMIN);
        }
        
        log.info("Roles initialization completed");
    }
    
    private void initializeAdminUser() {
        if (!StringUtils.hasText(adminPassword)) {
            log.info("Admin password not provided, skipping admin user creation");
            return;
        }
        
        // Check if admin user already exists
        if (userService.existsByUsername(Constants.DEFAULT_ADMIN_USERNAME)) {
            log.info("Admin user already exists");
            return;
        }
        
        // Create admin user
        User adminUser = new User(
            Constants.DEFAULT_ADMIN_USERNAME,
            Constants.DEFAULT_ADMIN_EMAIL,
            passwordEncoder.encode(adminPassword)
        );
        
        // Add both roles to admin
        Role userRole = roleRepository.findByName(Constants.ROLE_USER)
            .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));
        Role adminRole = roleRepository.findByName(Constants.ROLE_ADMIN)
            .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN not found"));
        
        adminUser.addRole(userRole);
        adminUser.addRole(adminRole);
        
        userService.save(adminUser);
        log.info("Created admin user: {}", Constants.DEFAULT_ADMIN_USERNAME);
    }
}