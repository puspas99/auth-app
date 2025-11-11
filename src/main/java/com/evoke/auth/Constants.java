package com.evoke.auth;

public final class Constants {
    
    // JWT Constants
    public static final String JWT_HEADER = "Authorization";
    public static final String JWT_TOKEN_PREFIX = "Bearer ";
    public static final String JWT_CLAIM_USERNAME = "username";
    public static final String JWT_CLAIM_AUTHORITIES = "authorities";
    public static final String JWT_CLAIM_USER_ID = "userId";
    
    // Role Constants
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    
    // Default Values
    public static final String DEFAULT_ADMIN_USERNAME = "admin";
    public static final String DEFAULT_ADMIN_EMAIL = "admin@evoke.com";
    
    // API Paths
    public static final String API_AUTH_BASE = "/api/v1/auth";
    public static final String API_USERS_BASE = "/api/v1/users";
    public static final String API_ADMIN_BASE = "/api/v1/admin";
    
    // Token Types
    public static final String TOKEN_TYPE_BEARER = "Bearer";
    
    // Security Constants
    public static final int MIN_PASSWORD_LENGTH = 6;
    public static final int MAX_PASSWORD_LENGTH = 100;
    public static final int MIN_USERNAME_LENGTH = 3;
    public static final int MAX_USERNAME_LENGTH = 50;
    
    // Pagination
    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;
    
    private Constants() {
        // Utility class - prevent instantiation
    }
}