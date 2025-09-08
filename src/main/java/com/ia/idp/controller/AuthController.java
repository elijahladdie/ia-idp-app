package com.ia.idp.controller;

import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.AuthorizeRequest;
import com.ia.idp.dto.LoginRequest;
import com.ia.idp.dto.LogoutRequest;
import com.ia.idp.dto.OAuthTokenResponse;
import com.ia.idp.dto.RefreshTokenRequest;
import com.ia.idp.dto.RegisterRequest;
import com.ia.idp.dto.TokenRequest;
import com.ia.idp.entity.AuthorizationCode;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.entity.User;
import com.ia.idp.service.AuthenticationService;
import com.ia.idp.service.AuthorizationCodeService;
import com.ia.idp.service.JwtService;
import com.ia.idp.service.LinkedInService;
import com.ia.idp.service.OAuthClientService;
import com.ia.idp.utils.ResponseHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.ui.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private LinkedInService linkedInService;

    @Autowired
    private OAuthClientService oAuthClientService;

    @Autowired
    private AuthorizationCodeService authorizationCodeService;

    @Autowired
    private JwtService jwtService;
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
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
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

    /**
     * OAUTH 2.0 AUTHORIZATION ENDPOINT
     * 
     * OAuth 2.0 Authorization Code Flow - Step 1: Authorization Request
     * Third-party applications redirect users here to request authorization.
     * 
     * Flow:
     * 1. Client app redirects user to this endpoint with client_id, redirect_uri, etc.
     * 2. User authenticates (if not already authenticated)
     * 3. User grants consent (if required)
     * 4. System generates authorization code
     * 5. Redirects back to client with authorization code
     * 
     * @param clientId Client identifier registered in admin panel
     * @param redirectUri Where to redirect after authorization
     * @param responseType Must be "code" for authorization code flow
     * @param scope Requested permissions (optional)
     * @param state CSRF protection parameter (recommended)
     * @param codeChallenge PKCE code challenge (optional)
     * @param codeChallengeMethod PKCE challenge method (optional)
     * @param session HTTP session for user authentication
     * @param response HTTP response for redirects
     * @return Redirect to client app with authorization code or error
     */
    @GetMapping("/authorize")
    public void authorizeEndpoint(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            HttpSession session,
            HttpServletResponse response) throws IOException {

        try {
            // Validate response_type
            if (!"code".equals(responseType)) {
                redirectWithError(redirectUri, "unsupported_response_type", 
                    "Only 'code' response_type is supported", state, response);
                return;
            }

            // Validate and get OAuth client
            OAuthClient client = oAuthClientService.getClientById(clientId);
            if (client == null || !client.isActive()) {
                redirectWithError(redirectUri, "invalid_client", 
                    "Invalid or inactive client", state, response);
                return;
            }

            // Validate redirect URI
            if (!client.isRedirectUriValid(redirectUri)) {
                redirectWithError(redirectUri, "invalid_request", 
                    "Invalid redirect_uri", state, response);
                return;
            }

            // Check if client supports authorization_code grant
            if (!client.isGrantTypeAllowed(OAuthClient.GrantType.AUTHORIZATION_CODE)) {
                redirectWithError(redirectUri, "unauthorized_client", 
                    "Client not authorized for authorization_code grant", state, response);
                return;
            }

            // Check if user is authenticated
            String userEmail = (String) session.getAttribute("user_email");
            if (userEmail == null) {
                // Redirect to login with return URL
                String returnUrl = buildAuthorizeUrl(clientId, redirectUri, responseType, scope, state, 
                    codeChallenge, codeChallengeMethod);
                response.sendRedirect("/login.html?return_url=" + URLEncoder.encode(returnUrl, StandardCharsets.UTF_8));
                return;
            }

            // Get authenticated user
            User user = authenticationService.getUserByEmail(userEmail);
            if (user == null || !user.getIsActive()) {
                redirectWithError(redirectUri, "access_denied", 
                    "User not found or inactive", state, response);
                return;
            }

            // Generate authorization code
            AuthorizationCode authCode = authorizationCodeService.generateAuthorizationCode(
                user, client, redirectUri, scope, state, codeChallenge, codeChallengeMethod);

            // Redirect back to client with authorization code
            String redirectUrl = buildSuccessRedirectUrl(redirectUri, authCode.getCode(), state);
            logger.info("Authorization code granted for user {} and client {}", user.getId(), clientId);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            logger.error("Error in authorization endpoint", e);
            redirectWithError(redirectUri, "server_error", 
                "Internal server error", state, response);
        }
    }

    /**
     * OAUTH 2.0 TOKEN ENDPOINT
     * 
     * OAuth 2.0 Authorization Code Flow - Step 2: Token Exchange
     * Client applications exchange authorization codes for access tokens.
     * 
     * @param request Token request containing grant_type, code, client credentials, etc.
     * @return OAuth token response with access_token and refresh_token
     */
    @GetMapping("/token")
    public ResponseEntity<OAuthTokenResponse> tokenEndpoint(@Valid @RequestParam TokenRequest request) {
        try {
            logger.info("Token request received for client: {}", request.getClientId());

            // Validate client
            OAuthClient client = oAuthClientService.getClientById(request.getClientId());
            if (client == null || !client.isActive()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("invalid_client", "Invalid or inactive client"));
            }

            // Validate client secret (if provided)
            if (request.getClientSecret() != null) {
                // TODO: Implement client secret validation
                // For now, we'll skip secret validation for public clients
            }

            if ("authorization_code".equals(request.getGrantType())) {
                return handleAuthorizationCodeGrant(request, client);
            } else if ("refresh_token".equals(request.getGrantType())) {
                return handleRefreshTokenGrant(request, client);
            } else {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("unsupported_grant_type", "Grant type not supported"));
            }

        } catch (Exception e) {
            logger.error("Error in token endpoint", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse("server_error", "Internal server error"));
        }
    }

    private ResponseEntity<OAuthTokenResponse> handleAuthorizationCodeGrant(TokenRequest request, OAuthClient client) {
        // Validate required parameters
        if (request.getCode() == null || request.getRedirectUri() == null) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_request", "Missing required parameters"));
        }

        // Validate and consume authorization code
        Optional<AuthorizationCode> authCodeOpt = authorizationCodeService.validateAndConsumeCode(request.getCode());
        if (authCodeOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_grant", "Invalid or expired authorization code"));
        }

        AuthorizationCode authCode = authCodeOpt.get();

        // Validate client matches
        if (!authCode.getClient().getClientId().equals(client.getClientId())) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_grant", "Authorization code was not issued to this client"));
        }

        // Validate redirect URI matches
        if (!authCode.getRedirectUri().equals(request.getRedirectUri())) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_grant", "Redirect URI mismatch"));
        }

        // Validate PKCE if present
        if (!authorizationCodeService.validatePKCE(authCode, request.getCodeVerifier())) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_grant", "PKCE validation failed"));
        }

        // Generate tokens
        User user = authCode.getUser();
        String accessToken = jwtService.generateAccessToken(user);
        long expiresIn = jwtService.getAccessTokenExpirationMs() / 1000;

        // For OAuth clients, we can optionally issue refresh tokens
        String refreshToken = null;
        if (client.isGrantTypeAllowed(OAuthClient.GrantType.REFRESH_TOKEN)) {
            // Generate refresh token - we'll create a simple implementation for now
            // In a full implementation, you'd want to create OAuth-specific refresh tokens
            refreshToken = generateOAuthRefreshToken(user);
        }

        OAuthTokenResponse tokenResponse = new OAuthTokenResponse(accessToken, refreshToken, expiresIn, authCode.getScope());
        
        logger.info("Access token issued for user {} and client {}", user.getId(), client.getClientId());
        return ResponseEntity.ok(tokenResponse);
    }

    private ResponseEntity<OAuthTokenResponse> handleRefreshTokenGrant(TokenRequest request, OAuthClient client) {
        if (request.getRefreshToken() == null) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_request", "Missing refresh_token parameter"));
        }

        if (!client.isGrantTypeAllowed(OAuthClient.GrantType.REFRESH_TOKEN)) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("unauthorized_client", "Client not authorized for refresh_token grant"));
        }

        try {
            // Use existing refresh token logic
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
            refreshRequest.setRefreshToken(request.getRefreshToken());
            
            AuthResponse authResponse = authenticationService.refreshToken(refreshRequest);
            
            OAuthTokenResponse tokenResponse = new OAuthTokenResponse(
                authResponse.getAccessToken(), 
                authResponse.getRefreshToken(), 
                authResponse.getExpiresIn(), 
                request.getScope()
            );
            
            return ResponseEntity.ok(tokenResponse);
            
        } catch (Exception e) {
            logger.warn("Refresh token validation failed", e);
            return ResponseEntity.badRequest()
                .body(createErrorResponse("invalid_grant", "Invalid refresh token"));
        }
    }

    private void redirectWithError(String redirectUri, String error, String errorDescription, 
                                 String state, HttpServletResponse response) throws IOException {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("error=").append(URLEncoder.encode(error, StandardCharsets.UTF_8));
        url.append("&error_description=").append(URLEncoder.encode(errorDescription, StandardCharsets.UTF_8));
        
        if (state != null) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        
        response.sendRedirect(url.toString());
    }

    private String buildAuthorizeUrl(String clientId, String redirectUri, String responseType, 
                                   String scope, String state, String codeChallenge, String codeChallengeMethod) {
        StringBuilder url = new StringBuilder("/auth/authorize");
        url.append("?client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
        url.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8));
        url.append("&response_type=").append(URLEncoder.encode(responseType, StandardCharsets.UTF_8));
        
        if (scope != null) {
            url.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        if (state != null) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        if (codeChallenge != null) {
            url.append("&code_challenge=").append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8));
        }
        if (codeChallengeMethod != null) {
            url.append("&code_challenge_method=").append(URLEncoder.encode(codeChallengeMethod, StandardCharsets.UTF_8));
        }
        
        return url.toString();
    }

    private String buildSuccessRedirectUrl(String redirectUri, String code, String state) {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));
        
        if (state != null) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        
        return url.toString();
    }

    private OAuthTokenResponse createErrorResponse(String error, String errorDescription) {
        OAuthTokenResponse errorResponse = new OAuthTokenResponse();
        // Note: In a real implementation, you might want a separate error response DTO
        // For now, we'll use the token response structure
        return errorResponse;
    }

    private String generateOAuthRefreshToken(User user) {
        // For now, use the existing authentication service to generate a refresh token
        // In a full OAuth implementation, you might want separate refresh token management
        try {
            RegisterRequest tempRequest = new RegisterRequest();
            tempRequest.setEmail(user.getEmail());
            tempRequest.setFirstName(user.getFirstName());
            tempRequest.setLastName(user.getLastName());
            tempRequest.setPassword("temp"); // Won't be used since user already exists
            
            // This is a workaround - in production, you'd have dedicated OAuth refresh token generation
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setEmail(user.getEmail());
            loginRequest.setPassword("temp"); // This won't work, but we need a better approach
            
            // For now, return null - refresh tokens for OAuth clients need proper implementation
            return null;
        } catch (Exception e) {
            logger.warn("Could not generate OAuth refresh token for user {}", user.getId());
            return null;
        }
    }

}
