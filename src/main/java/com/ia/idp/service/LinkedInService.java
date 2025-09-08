package com.ia.idp.service;

import com.ia.idp.config.LinkedInConfig;
import com.ia.idp.repository.RefreshTokenRepository;
import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.LinkedInAuthRequest;
import com.ia.idp.entity.User;
import com.ia.idp.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Transactional
public class LinkedInService {

    private static final Logger logger = LoggerFactory.getLogger(LinkedInService.class);
    
    // In-memory cache for OAuth state parameters (use Redis in production)
    private final Map<String, StateInfo> oauthStateCache = new ConcurrentHashMap<>();

    @Autowired
    private LinkedInConfig linkedInConfig;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private final WebClient webClient;

    public LinkedInService() {
        this.webClient = WebClient.builder()
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .build();
    }

    public AuthResponse authenticateWithLinkedIn(LinkedInAuthRequest request) {
        logger.info("Attempting LinkedIn OAuth authentication");

        try {
            // Exchange authorization code for access token
            String accessToken = exchangeCodeForToken(request.getCode());

            // Fetch user profile from LinkedIn
            LinkedInUserProfile profile = fetchUserProfile(accessToken);

            // Find or create user
            User user = findOrCreateUser(profile);

            // Generate authentication response
            return generateAuthResponse(user);

        } catch (Exception e) {
            logger.error("LinkedIn authentication failed", e);
            throw new RuntimeException("LinkedIn authentication failed: " + e.getMessage(), e);
        }
    }

    private String exchangeCodeForToken(String code) {
        logger.debug("Exchanging authorization code for access token");

        try {
            Map<String, Object> response = webClient.post()
                .uri(linkedInConfig.getTokenUri())
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                    .with("code", code)
                    .with("redirect_uri", linkedInConfig.getRedirectUri())
                    .with("client_id", linkedInConfig.getClientId())
                    .with("client_secret", linkedInConfig.getClientSecret()))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            if (response == null || !response.containsKey("access_token")) {
                throw new RuntimeException("Invalid response from LinkedIn token endpoint");
            }

            return (String) response.get("access_token");

        } catch (WebClientResponseException e) {
            logger.error("Failed to exchange code for token: {}", e.getResponseBodyAsString());
            throw new RuntimeException("Failed to exchange authorization code for token", e);
        }
    }

    private LinkedInUserProfile fetchUserProfile(String accessToken) {
        logger.debug("Fetching user profile from LinkedIn");
        try {
            // Fetch user profile using the new userinfo endpoint
            Map<String, Object> profileResponse = webClient.get()
                .uri(linkedInConfig.getUserInfoUri())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            if (profileResponse == null) {
                throw new RuntimeException("No response from LinkedIn userinfo endpoint");
            }

            return parseLinkedInProfile(profileResponse);

        } catch (WebClientResponseException e) {

            logger.error("Failed to fetch user profile: {}", e.getResponseBodyAsString());
            throw new RuntimeException("Failed to fetch user profile from LinkedIn", e);
        }
    }

    private LinkedInUserProfile parseLinkedInProfile(Map<String, Object> profileResponse) {
        try {
            // Parse using new LinkedIn userinfo endpoint format
            String id = (String) profileResponse.get("sub"); // 'sub' is the user ID in userinfo
            String email = (String) profileResponse.get("email");
            String givenName = (String) profileResponse.get("given_name");
            String familyName = (String) profileResponse.get("family_name");
            
            // Fallback to 'name' if given_name/family_name not available
            if (givenName == null || familyName == null) {
                String fullName = (String) profileResponse.get("name");
                if (fullName != null) {
                    String[] nameParts = fullName.split(" ", 2);
                    givenName = nameParts[0];
                    familyName = nameParts.length > 1 ? nameParts[1] : "";
                }
            }

            if (email == null) {
                throw new RuntimeException("Unable to retrieve email address from LinkedIn");
            }
            
            if (id == null) {
                throw new RuntimeException("Unable to retrieve user ID from LinkedIn");
            }

            return new LinkedInUserProfile(id, email, givenName != null ? givenName : "", familyName != null ? familyName : "");

        } catch (Exception e) {
            logger.error("Failed to parse LinkedIn profile response", e);
            throw new RuntimeException("Failed to parse LinkedIn profile data", e);
        }
    }

    private User findOrCreateUser(LinkedInUserProfile profile) {
        logger.debug("Finding or creating user for LinkedIn profile: {}", profile.getEmail());

        // First, try to find user by LinkedIn provider ID
        Optional<User> existingUser = userRepository.findByProviderAndProviderId(
            User.AuthProvider.LINKEDIN, profile.getId()
        );

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            // Ensure LinkedIn users are always email verified
            if (!user.getEmailVerified()) {
                user.setEmailVerified(true);
                user = userRepository.save(user);
            }
            logger.info("Found existing LinkedIn user: {}", user.getId());
            return user;
        }

        // Check if user exists with same email but different provider
        Optional<User> emailUser = userRepository.findByEmail(profile.getEmail());
        if (emailUser.isPresent()) {
            User user = emailUser.get();
            // Link LinkedIn account to existing user
            user.setProvider(User.AuthProvider.LINKEDIN);
            user.setProviderId(profile.getId());
            user.setEmailVerified(true); // LinkedIn emails are pre-verified
            user = userRepository.save(user);
            logger.info("Linked LinkedIn account to existing user: {}", user.getId());
            return user;
        }

        // Create new user with auto-verified email for LinkedIn
        User newUser = new User(profile.getEmail(), profile.getFirstName(), profile.getLastName(), User.AuthProvider.LINKEDIN);
        newUser.setProviderId(profile.getId());
        newUser.setEmailVerified(true); // LinkedIn emails are automatically verified
        newUser = userRepository.save(newUser);
        
        logger.info("Created new LinkedIn user with auto-verified email: {}", newUser.getId());
        return newUser;
    }

    /**
     * Generate OAuth state parameter for CSRF protection
     */
    public String generateOAuthState() {
        String state = UUID.randomUUID().toString();
        StateInfo stateInfo = new StateInfo("idp-service", System.currentTimeMillis() + Duration.ofMinutes(10).toMillis());
        oauthStateCache.put(state, stateInfo);
        
        // Clean up expired states
        cleanupExpiredStates();
        
        logger.debug("Generated OAuth state: {}", state);
        return state;
    }
    
    /**
     * Build LinkedIn authorization URL with IDP's own credentials
     */
    public String buildLinkedInAuthUrl(String state) {
        return linkedInConfig.getAuthorizationUri() +
            "?response_type=code" +
            "&client_id=" + linkedInConfig.getClientId() +
            "&redirect_uri=" + linkedInConfig.getRedirectUri() +
            "&state=" + state +
            "&scope=openid%20profile%20email";
    }
    
    /**
     * Process LinkedIn OAuth callback with authorization code
     */
    public AuthResponse processLinkedInCallback(String code, String state, HttpServletRequest request) {
        logger.info("Processing LinkedIn OAuth callback");
        
        // Validate state parameter for CSRF protection
        validateOAuthState(state);
        
        try {
            // Exchange authorization code for access token
            String accessToken = exchangeCodeForToken(code);
            
            // Fetch user profile from LinkedIn
            LinkedInUserProfile profile = fetchUserProfile(accessToken);
            
            // Find or create user (auto-verified for LinkedIn)
            User user = findOrCreateUser(profile);
            
            // Store user in session for success page
            if (request != null) {
                request.getSession().setAttribute("authenticated_user", user);
            }
            
            // Generate authentication response
            return generateAuthResponse(user);
            
        } catch (Exception e) {
            logger.error("LinkedIn OAuth callback processing failed", e);
            throw new RuntimeException("LinkedIn authentication failed: " + e.getMessage(), e);
        } finally {
            // Remove used state
            oauthStateCache.remove(state);
        }
    }
    
    /**
     * Validate OAuth state parameter
     */
    private void validateOAuthState(String state) {
        StateInfo stateInfo = oauthStateCache.get(state);
        
        if (stateInfo == null) {
            throw new RuntimeException("Invalid OAuth state parameter");
        }
        
        if (System.currentTimeMillis() > stateInfo.getExpiryTime()) {
            oauthStateCache.remove(state);
            throw new RuntimeException("OAuth state parameter has expired");
        }
    }
    
    /**
     * Clean up expired state parameters
     */
    private void cleanupExpiredStates() {
        long currentTime = System.currentTimeMillis();
        oauthStateCache.entrySet().removeIf(entry -> currentTime > entry.getValue().getExpiryTime());
    }
    
    /**
     * State information for OAuth CSRF protection
     */
    private static class StateInfo {
        private final String service;
        private final long expiryTime;
        
        public StateInfo(String service, long expiryTime) {
            this.service = service;
            this.expiryTime = expiryTime;
        }
        
        public String getService() { return service; }
        public long getExpiryTime() { return expiryTime; }
    }

    private static class LinkedInUserProfile {
        private final String id;
        private final String email;
        private final String firstName;
        private final String lastName;

        public LinkedInUserProfile(String id, String email, String firstName, String lastName) {
            this.id = id;
            this.email = email;
            this.firstName = firstName;
            this.lastName = lastName;
        }

        public String getId() { return id; }
        public String getEmail() { return email; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
    }

    private AuthResponse generateAuthResponse(User user) {
        // Generate access token
        String accessToken = jwtService.generateAccessToken(user);

        // Generate refresh token
        String refreshTokenValue = generateSecureToken();
        String refreshTokenHash = hashToken(refreshTokenValue);

        // Save refresh token
        com.ia.idp.entity.RefreshToken refreshToken = new com.ia.idp.entity.RefreshToken(
            refreshTokenHash,
            user,
            java.time.LocalDateTime.now().plusSeconds(jwtService.getRefreshTokenExpirationMs() / 1000)
        );
        refreshTokenRepository.save(refreshToken);

        // Create user info
        AuthResponse.UserInfo userInfo = new AuthResponse.UserInfo(
            user.getId(), user.getEmail(), user.getFirstName(), 
            user.getLastName(), user.getEmailVerified(), user.getProvider().name(), user.getRole().name()
        );

        return new AuthResponse(
            accessToken,
            refreshTokenValue,
            jwtService.getAccessTokenExpirationMs() / 1000,
            userInfo
        );
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
