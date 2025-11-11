package com.evoke.auth.integration;

import com.evoke.auth.dto.requests.LoginRequest;
import com.evoke.auth.dto.requests.RegisterRequest;
import com.evoke.auth.dto.responses.ApiResponse;
import com.evoke.auth.dto.responses.TokenResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.annotation.DirtiesContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthIntegrationTest {
    
    @LocalServerPort
    private int port;
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine")
        .withDatabaseName("testdb")
        .withUsername("postgres")
        .withPassword("postgres");

    @DynamicPropertySource
    static void configureDataSource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", POSTGRES::getDriverClassName);
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }
    
    @Test
    void fullAuthFlow_RegisterLoginAndAccessProtectedEndpoint_Success() throws Exception {
        String baseUrl = "http://localhost:" + port;
        
        // 1. Register a new user
        RegisterRequest registerRequest = new RegisterRequest("testuser", "test@example.com", "password123");
        
        ResponseEntity<String> registerResponse = restTemplate.postForEntity(
            baseUrl + "/api/v1/auth/register", registerRequest, String.class);
        
        assertEquals(HttpStatus.CREATED, registerResponse.getStatusCode());
        
        ApiResponse<Map<String, Object>> registerApiResponse = objectMapper.readValue(
            registerResponse.getBody(), new TypeReference<ApiResponse<Map<String, Object>>>() {});
        
        assertTrue(registerApiResponse.isSuccess());
        assertEquals("User registered successfully", registerApiResponse.getMessage());
        assertNotNull(registerApiResponse.getData());
        assertEquals("testuser", registerApiResponse.getData().get("username"));
        
        // 2. Login with the registered user
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");
        
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(
            baseUrl + "/api/v1/auth/login", loginRequest, String.class);
        
        assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
        
        ApiResponse<TokenResponse> loginApiResponse = objectMapper.readValue(
            loginResponse.getBody(), new TypeReference<ApiResponse<TokenResponse>>() {});
        
        assertTrue(loginApiResponse.isSuccess());
        assertEquals("Login successful", loginApiResponse.getMessage());
        assertNotNull(loginApiResponse.getData());
        
        TokenResponse tokenResponse = loginApiResponse.getData();
        assertNotNull(tokenResponse.getAccessToken());
        assertNotNull(tokenResponse.getRefreshToken());
        assertEquals("Bearer", tokenResponse.getTokenType());
        
        // 3. Access protected endpoint with JWT token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenResponse.getAccessToken());
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> profileResponse = restTemplate.exchange(
            baseUrl + "/api/v1/users/me", HttpMethod.GET, entity, String.class);
        
        assertEquals(HttpStatus.OK, profileResponse.getStatusCode());
        
        ApiResponse<Map<String, Object>> profileApiResponse = objectMapper.readValue(
            profileResponse.getBody(), new TypeReference<ApiResponse<Map<String, Object>>>() {});
        
        assertTrue(profileApiResponse.isSuccess());
        assertEquals("User profile retrieved", profileApiResponse.getMessage());
        assertNotNull(profileApiResponse.getData());
        
        Map<String, Object> userData = profileApiResponse.getData();
        assertEquals("testuser", userData.get("username"));
        assertEquals("test@example.com", userData.get("email"));
        assertTrue((Boolean) userData.get("active"));
        
        // 4. Try to access admin endpoint (should fail)
        ResponseEntity<String> adminResponse = restTemplate.exchange(
            baseUrl + "/api/v1/admin/users", HttpMethod.GET, entity, String.class);
        
        assertEquals(HttpStatus.FORBIDDEN, adminResponse.getStatusCode());
    }
    
    @Test
    void accessProtectedEndpointWithoutToken_ShouldReturn401() {
        String baseUrl = "http://localhost:" + port;
        
        ResponseEntity<String> response = restTemplate.getForEntity(
            baseUrl + "/api/v1/users/me", String.class);
        
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void accessProtectedEndpointWithInvalidToken_ShouldReturn401() {
        String baseUrl = "http://localhost:" + port;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth("invalid.jwt.token");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            baseUrl + "/api/v1/users/me", HttpMethod.GET, entity, String.class);
        
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void loginWithInvalidCredentials_ShouldReturn401() throws Exception {
        String baseUrl = "http://localhost:" + port;
        
        LoginRequest loginRequest = new LoginRequest("nonexistent", "wrongpassword");
        
        ResponseEntity<String> response = restTemplate.postForEntity(
            baseUrl + "/api/v1/auth/login", loginRequest, String.class);
        
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        
        ApiResponse<Void> apiResponse = objectMapper.readValue(
            response.getBody(), new TypeReference<ApiResponse<Void>>() {});
        
        assertFalse(apiResponse.isSuccess());
        assertEquals("Invalid credentials", apiResponse.getMessage());
    }
    
    @Test
    void registerWithDuplicateUsername_ShouldReturn400() throws Exception {
        String baseUrl = "http://localhost:" + port;
        
        // Register first user
        RegisterRequest firstRequest = new RegisterRequest("duplicate", "first@example.com", "password123");
        restTemplate.postForEntity(baseUrl + "/api/v1/auth/register", firstRequest, String.class);
        
        // Try to register with same username
        RegisterRequest secondRequest = new RegisterRequest("duplicate", "second@example.com", "password123");
        ResponseEntity<String> response = restTemplate.postForEntity(
            baseUrl + "/api/v1/auth/register", secondRequest, String.class);
        
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        
        ApiResponse<Void> apiResponse = objectMapper.readValue(
            response.getBody(), new TypeReference<ApiResponse<Void>>() {});
        
        assertFalse(apiResponse.isSuccess());
        assertTrue(apiResponse.getMessage().contains("Username already exists"));
    }
}