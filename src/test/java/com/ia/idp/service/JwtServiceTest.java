package com.ia.idp.service;

import com.ia.idp.config.JwtConfig;
import com.ia.idp.entity.User;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtConfig jwtConfig;

    @InjectMocks
    private JwtService jwtService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User("test@example.com", "John", "Doe", User.AuthProvider.LOCAL);
        testUser.setId(1L);
        testUser.setEmailVerified(true);

        // Mock JWT configuration - no more Secret class needed
        JwtConfig.AccessToken accessToken = new JwtConfig.AccessToken();
        accessToken.setExpiration(900000L); // 15 minutes

        when(jwtConfig.getAccessToken()).thenReturn(accessToken);
        when(jwtConfig.getIssuer()).thenReturn("https://idp.companyia.com");
        when(jwtConfig.getKeyId()).thenReturn("key-1");
        
        // Initialize the service to generate keys
        jwtService.init();
    }

    @Test
    void testGenerateAccessToken() {
        String token = jwtService.generateAccessToken(testUser);
        
        assertNotNull(token);
        assertTrue(token.length() > 0);
    }

    @Test
    void testGetJwksResponse() {
        var jwks = jwtService.getJwksResponse();
        
        assertNotNull(jwks);
        assertTrue(jwks.containsKey("keys"));
        assertNotNull(jwks.get("keys"));
    }
}
