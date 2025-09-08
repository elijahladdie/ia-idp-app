package com.ia.idp.controller;

import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.LoginRequest;
import com.ia.idp.dto.RegisterRequest;
import com.ia.idp.service.AuthenticationService;
import com.ia.idp.service.LinkedInService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationService authenticationService;

    @MockBean
    private LinkedInService linkedInService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testRegisterSuccess() throws Exception {
        RegisterRequest request = new RegisterRequest(
            "test@example.com", 
            "Password123!", 
            "John", 
            "Doe"
        );

        AuthResponse response = new AuthResponse(
            "access-token", 
            "refresh-token", 
            900, 
            new AuthResponse.UserInfo(1L, "test@example.com", "John", "Doe", true, "LOCAL", "ROLE_USER")
        );

        when(authenticationService.register(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.access_token").value("access-token"))
                .andExpect(jsonPath("$.user.email").value("test@example.com"));
    }

    @Test
    void testLoginSuccess() throws Exception {
        LoginRequest request = new LoginRequest("test@example.com", "Password123!");

        AuthResponse response = new AuthResponse(
            "access-token", 
            "refresh-token", 
            900, 
            new AuthResponse.UserInfo(1L, "test@example.com", "John", "Doe", true, "LOCAL", "ROLE_USER")
        );

        when(authenticationService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access-token"))
                .andExpect(jsonPath("$.user.email").value("test@example.com"));
    }

    @Test
    void testRegisterValidationFailure() throws Exception {
        RegisterRequest request = new RegisterRequest("", "", "", "");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"));
    }
}
