package com.evoke.auth.controller;

import com.evoke.auth.dto.responses.ApiResponse;
import com.evoke.auth.entity.User;
import com.evoke.auth.security.CustomUserDetails;
import com.evoke.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User management endpoints")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {
    
    private final UserService userService;
    
    @GetMapping("/api/v1/users/me")
    @Operation(summary = "Get current user profile")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getCurrentUser(Authentication authentication) {
        try {
            String username = (String) authentication.getPrincipal();
            User user = userService.findByUsernameWithRoles(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
            
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            userData.put("active", user.isActive());
            userData.put("roles", user.getRoles().stream().map(role -> role.getName()).toList());
            userData.put("createdAt", user.getCreatedAt());
            userData.put("updatedAt", user.getUpdatedAt());
            
            return ResponseEntity.ok(ApiResponse.success("User profile retrieved", userData));
        } catch (Exception e) {
            log.error("Error getting current user", e);
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Unable to get user profile"));
        }
    }
    
    @GetMapping("/api/v1/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get all users (Admin only)")
    public ResponseEntity<ApiResponse<Page<Map<String, Object>>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDirection) {
        
        try {
            Sort.Direction direction = sortDirection.equalsIgnoreCase("desc") 
                ? Sort.Direction.DESC 
                : Sort.Direction.ASC;
            
            Pageable pageable = PageRequest.of(page, Math.min(size, 100), Sort.by(direction, sortBy));
            Page<User> users = userService.findAll(pageable);
            
            Page<Map<String, Object>> userPage = users.map(user -> {
                Map<String, Object> userData = new HashMap<>();
                userData.put("id", user.getId());
                userData.put("username", user.getUsername());
                userData.put("email", user.getEmail());
                userData.put("active", user.isActive());
                userData.put("roles", user.getRoles().stream().map(role -> role.getName()).toList());
                userData.put("createdAt", user.getCreatedAt());
                userData.put("updatedAt", user.getUpdatedAt());
                return userData;
            });
            
            return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", userPage));
        } catch (Exception e) {
            log.error("Error getting all users", e);
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Unable to get users"));
        }
    }
    
    @PutMapping("/api/v1/admin/users/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Deactivate user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> deactivateUser(@PathVariable Long userId) {
        try {
            userService.deactivateUser(userId);
            return ResponseEntity.ok(ApiResponse.success("User deactivated successfully"));
        } catch (Exception e) {
            log.error("Error deactivating user", e);
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Unable to deactivate user"));
        }
    }
    
    @PutMapping("/api/v1/admin/users/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Activate user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> activateUser(@PathVariable Long userId) {
        try {
            userService.activateUser(userId);
            return ResponseEntity.ok(ApiResponse.success("User activated successfully"));
        } catch (Exception e) {
            log.error("Error activating user", e);
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Unable to activate user"));
        }
    }
}