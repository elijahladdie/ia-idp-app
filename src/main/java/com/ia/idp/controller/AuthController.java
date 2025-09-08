package com.ia.idp.controller;

import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.LoginRequest;
import com.ia.idp.dto.LogoutRequest;
import com.ia.idp.dto.RefreshTokenRequest;
import com.ia.idp.dto.RegisterRequest;
import com.ia.idp.entity.User;
import com.ia.idp.service.AuthenticationService;
import com.ia.idp.service.LinkedInService;
import com.ia.idp.utils.ResponseHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.ui.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private LinkedInService linkedInService;
/**
     * REGISTRATION SECTION - Normal Email/Password Registration
     * 
     * Registers a new user with email and password credentials.
     * Issues JWT access and refresh tokens upon successful registration.
     * Sends email verification link to the user.
     * 
     * @param request RegisterRequest containing email, password, firstName, lastName
     * @return AuthResponse with JWT tokens and user information
     */
    @PostMapping("/register")
    public ResponseEntity register(@Valid @RequestBody RegisterRequest request) {
        try {
            logger.info("Registration request received for email: {}", request.getEmail());
            AuthResponse response = authenticationService.register(request);
            return ResponseHandler.responseSuccess(201, "User registered successfully", response);
        } catch (Exception e) {
            logger.error("Registration failed for email: {}", request.getEmail(), e);
            return ResponseHandler.responseError(400, e.getMessage(), null);
        }
    }

    /**
     * LOGIN SECTION - Email/Password Authentication
     * 
     * Authenticates existing users with email and password.
     * Issues new JWT access and refresh tokens upon successful login.
     * 
     * @param request LoginRequest containing email and password
     * @return AuthResponse with JWT tokens and user information
     */
    @PostMapping("/login")
    public ResponseEntity login(@Valid @RequestBody LoginRequest request) {
        try {
            logger.info("Login request received for email: {}", request.getEmail());
            AuthResponse response = authenticationService.login(request);
            return ResponseHandler.responseSuccess(200, "Login successful", response);
        } catch (Exception e) {
            logger.error("Login failed for email: {}", request.getEmail(), e);
            return ResponseHandler.responseError(401, e.getMessage(), null);
        }
    }

    /**
     * LINKEDIN OAUTH REGISTRATION SECTION - Step 1: Initiate OAuth Flow
     * 
     * Initiates LinkedIn OAuth 2.0 authorization flow for user registration.
     * Uses the IDP's own LinkedIn credentials (client_id, client_secret, redirect_uri)
     * configured in application.properties to authenticate with LinkedIn.
     * Redirects user to LinkedIn login page where they authenticate with LinkedIn.
     * After LinkedIn authentication, user will be redirected back to our callback endpoint.
     * 
     * Flow:
     * 1. User clicks LinkedIn registration link
     * 2. System redirects to LinkedIn OAuth page using IDP's credentials
     * 3. User authenticates with LinkedIn
     * 4. LinkedIn redirects back with authorization code
     * 5. System exchanges code for LinkedIn user info
     * 6. System registers user in our database
     * 7. System issues JWT access and refresh tokens
     * 
     * @return HTTP 302 redirect to LinkedIn OAuth authorization page
     */
    @GetMapping("/linkedin")
    public ResponseEntity<String> initiateLinkedInAuth() {
        try {
            logger.info("LinkedIn OAuth initiation request received");
            
            String state = linkedInService.generateOAuthState();
            String authUrl = linkedInService.buildLinkedInAuthUrl(state);
            
            logger.info("Redirecting to LinkedIn OAuth URL: {}", authUrl);
            
            // Perform HTTP 302 redirect to LinkedIn OAuth page
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(authUrl))
                .build();
                
        } catch (Exception e) {
            logger.error("Failed to generate LinkedIn auth URL", e);
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("/auth/error?message=oauth_initiation_failed"))
                .build();
        }
    }

    /**
     * TOKEN REFRESH SECTION
     * 
     * Refreshes expired JWT access tokens using valid refresh tokens.
     * Issues new access and refresh tokens (refresh token rotation).
     * Validates refresh token and revokes old tokens for security.
     * 
     * @param request RefreshTokenRequest containing the refresh token
     * @return AuthResponse with new JWT access and refresh tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            logger.info("Token refresh request received");
            AuthResponse response = authenticationService.refreshToken(request);
            return ResponseHandler.responseSuccess(200, "Token refreshed successfully", response);
        } catch (Exception e) {
            logger.error("Token refresh failed", e);
            return ResponseHandler.responseError(401, e.getMessage(), null);
        }
    }

    /**
     * LOGOUT SECTION - Single Device Logout
     * 
     * Logs out user from current device by revoking the refresh token.
     * Access token will expire naturally (15 minutes).
     * 
     * @param request LogoutRequest containing refresh token and client ID
     * @return Success response confirming logout
     */
    @PostMapping("/logout")
    public ResponseEntity logout(@Valid @RequestBody LogoutRequest request) {
        try {
            logger.info("Logout request received");
            authenticationService.logout(request.getRefreshToken());
            return ResponseHandler.responseSuccess(200, "Logged out successfully", null);
        } catch (Exception e) {
            logger.error("Logout failed", e);
            return ResponseHandler.responseError(400, e.getMessage(), null);
        }
    }

    /**
     * LOGOUT SECTION - All Devices Logout
     * 
     * Logs out user from all devices by revoking all refresh tokens.
     * All access tokens will expire naturally (15 minutes).
     * 
     * @param request LogoutRequest containing refresh token and client ID
     * @return Success response confirming logout from all devices
     */
    @PostMapping("/logout-all")
    public ResponseEntity logoutAll(@Valid @RequestBody LogoutRequest request) {
        try {
            logger.info("Logout all devices request received");
            authenticationService.logoutAll(request.getRefreshToken());
            return ResponseHandler.responseSuccess(200, "Logged out from all devices successfully", null);
        } catch (Exception e) {
            logger.error("Logout all devices failed", e);
            return ResponseHandler.responseError(400, e.getMessage(), null);
        }
    }

    /**
     * EMAIL VERIFICATION SECTION
     * 
     * Verifies user email address using verification token sent via email.
     * Activates user account after successful email verification.
     * 
     * @param token Email verification token (24-hour expiry)
     * @return Success/failure response with verification status
     */
    @GetMapping("/verify-email")
    public ResponseEntity verifyEmail(@RequestParam("token") String token) {
        try {
            logger.info("Email verification request received");
            boolean verified = authenticationService.verifyEmail(token);
            
            if (verified) {
                Map<String, Object> data = Map.of("verified", true);
                return ResponseHandler.responseSuccess(200, "Email verified successfully", data);
            } else {
                Map<String, Object> data = Map.of("verified", false);
                return ResponseHandler.responseError(400, "Invalid or expired verification token", data);
            }
        } catch (Exception e) {
            logger.error("Email verification failed", e);
            return ResponseHandler.responseError(500, "Email verification failed", null);
        }
    }

    /**
     * LINKEDIN OAUTH REGISTRATION SECTION - Step 2: Handle OAuth Callback
     * 
     * Processes LinkedIn OAuth callback after user authentication.
     * Retrieves user information from LinkedIn, registers them in our system,
     * and issues JWT access and refresh tokens signed with our private key.
     * 
     * This endpoint completes the LinkedIn registration flow by:
     * 1. Validating the OAuth state parameter (CSRF protection)
     * 2. Exchanging authorization code for LinkedIn access token
     * 3. Fetching user profile information from LinkedIn API
     * 4. Creating/updating user record in our database
     * 5. Generating JWT access and refresh tokens
     * 6. Redirecting to success page with tokens
     * 
     * @param code Authorization code from LinkedIn
     * @param state OAuth state parameter for CSRF protection
     * @param error Optional error parameter if OAuth failed
     * @param request HTTP request for additional context
     * @return HTTP 302 redirect to success page with JWT tokens
     */
    @GetMapping("/linkedin/callback")
    public ResponseEntity<String> handleLinkedInCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            @RequestParam(value = "error", required = false) String error,
            HttpServletRequest request) {
        
        logger.info("LinkedIn OAuth callback received with code: {}, state: {}", 
                   code != null ? "[PRESENT]" : "[MISSING]", state);
        
        if (error != null) {
            logger.error("LinkedIn OAuth error: {}", error);
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("/auth/error?message=" + error))
                .build();
        }
        
        try {
            AuthResponse tokens = linkedInService.processLinkedInCallback(code, state, request);
            
            // Redirect to success page with user information (not tokens for security)
            String redirectUrl = "/auth/success";
            
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectUrl))
                .build();
                
        } catch (Exception e) {
            logger.error("Error processing LinkedIn callback: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("/auth/error?message=authentication_failed"))
                .build();
        }
    }

}
