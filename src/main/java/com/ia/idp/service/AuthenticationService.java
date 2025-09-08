package com.ia.idp.service;

import com.ia.idp.config.AppConfig;
import com.ia.idp.dto.*;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.entity.RefreshToken;
import com.ia.idp.entity.User;
import com.ia.idp.exception.AuthenticationException;
import com.ia.idp.exception.EmailNotVerifiedException;
import com.ia.idp.exception.InvalidTokenException;
import com.ia.idp.exception.UserAlreadyExistsException;
import com.ia.idp.repository.OAuthClientRepository;
import com.ia.idp.repository.RefreshTokenRepository;
import com.ia.idp.repository.UserRepository;

import org.hibernate.cfg.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private OAuthClientRepository oAuthClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private AppConfig appConfig;

    public AuthResponse register(RegisterRequest request) {
        logger.info("Attempting to register user with email: {}", request.getEmail());

        // Validate client
        OAuthClient client = validateClient(request.getClientId());

        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with email " + request.getEmail() + " already exists");
        }

        // Create new user
        User user = new User(request.getEmail(), request.getFirstName(), request.getLastName(), User.AuthProvider.LOCAL);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));

        // Standard registration always requires email verification (unless disabled globally)
        if (appConfig.isEmailVerificationRequired()) {
            String verificationToken = UUID.randomUUID().toString();
            user.setEmailVerificationToken(verificationToken);
            user.setEmailVerificationExpiresAt(LocalDateTime.now().plusHours(24));
            user.setEmailVerified(false);
            
            logger.info("Generated email verification token for user: {}", request.getEmail());
            logger.info("env email verification token for user: {}", request.getEmail());

        } else {
            user.setEmailVerified(true);
        }

        user = userRepository.save(user);
        logger.info("User registered successfully with ID: {} (email_verified: {})", user.getId(), user.getEmailVerified());
        if (appConfig.isEmailVerificationRequired() && !user.getEmailVerified()) {
            try {
                emailService.sendVerificationEmail(user);
                logger.info("Verification email sent to: {}", user.getEmail());
            } catch (Exception e) {
                logger.error("Failed to send verification email to: {}", user.getEmail(), e);
                // Don't fail registration if email sending fails
            }
        }
        return generateAuthResponse(user);
    }

    public AuthResponse login(LoginRequest request) {
        logger.info("Attempting to login user with email: {}", request.getEmail());

        // Validate client
        OAuthClient client = validateClient(request.getClientId());
        
        // we get app connected to this client and return the authorization

        // Find user by email
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("Invalid email or password");
        }

        User user = userOpt.get();

        // Check if user is active
        if (!user.getIsActive()) {
            throw new AuthenticationException("Account is disabled");
        }

        // Verify password
        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new AuthenticationException("Invalid email or password");
        }

        // Check email verification for LOCAL provider users only
        if (user.requiresEmailVerification() && !appConfig.isAllowUnverifiedLogin()) {
            throw new EmailNotVerifiedException("Email verification required. Please check your email and verify your account.");
        }

        // Update last login
        user.updateLastLogin();
        userRepository.save(user);

        logger.info("User logged in successfully: {}", user.getId());
        return generateAuthResponse(user);
    }

    public AuthResponse loginWithoutEmailVerification(LoginRequest request) {
        logger.info("Attempting admin login for user with email: {}", request.getEmail());

        // Find user by email
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("Invalid email or password");
        }

        User user = userOpt.get();

        // Check if user is active
        if (!user.getIsActive()) {
            throw new AuthenticationException("Account is disabled");
        }

        // Verify password
        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new AuthenticationException("Invalid email or password");
        }

        // Skip email verification for admin console access

        // Update last login
        user.updateLastLogin();
        userRepository.save(user);

        logger.info("Admin user logged in successfully: {}", user.getId());
        return generateAuthResponse(user);
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        logger.info("Attempting to refresh token");

        String tokenHash = hashToken(request.getRefreshToken());
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

        if (tokenOpt.isEmpty()) {
            throw new AuthenticationException("Invalid refresh token");
        }

        RefreshToken refreshToken = tokenOpt.get();
        
        // Check if token is expired or revoked
        if (!refreshToken.isValid()) {
            throw new InvalidTokenException("Refresh token is expired or revoked");
        }

        User user = refreshToken.getUser();

        // Check if user is still active
        if (!user.getIsActive()) {
            throw new AuthenticationException("Account is disabled");
        }

        // Revoke the old refresh token (single-use)
        refreshTokenRepository.delete(refreshToken);

        // Generate authentication response
        return generateAuthResponse(user);
    }

    public void logout(String refreshTokenValue) {
        logger.info("Attempting to logout (single device)");

        String tokenHash = hashToken(refreshTokenValue);
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

        if (tokenOpt.isPresent()) {
            RefreshToken refreshToken = tokenOpt.get();
            refreshTokenRepository.delete(refreshToken);
            logger.info("User logged out successfully (single device): {}", refreshToken.getUser().getId());
        }
    }

    public void logoutAll(String refreshTokenValue) {
        logger.info("Attempting to logout all devices");

        String tokenHash = hashToken(refreshTokenValue);
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

        if (tokenOpt.isPresent()) {
            RefreshToken refreshToken = tokenOpt.get();
            User user = refreshToken.getUser();
            refreshTokenRepository.revokeAllByUser(user);
            logger.info("User logged out from all devices: {}", user.getId());
        }
    }

    public boolean verifyEmail(String token) {
        logger.info("Attempting to verify email with token");

        Optional<User> userOpt = userRepository.findByEmailVerificationToken(token);
        if (userOpt.isEmpty()) {
            logger.warn("Invalid email verification token");
            return false;
        }

        User user = userOpt.get();

        // Check if token is expired
        if (user.isEmailVerificationExpired()) {
            logger.warn("Email verification token expired for user: {}", user.getId());
            return false;
        }

        // Verify email
        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiresAt(null);
        userRepository.save(user);

        logger.info("Email verified successfully for user: {}", user.getId());
        return true;
    }

    private AuthResponse generateAuthResponse(User user) {
        // Generate access token
        String accessToken = jwtService.generateAccessToken(user);

        // Generate refresh token
        String refreshTokenValue = generateSecureToken();
        String refreshTokenHash = hashToken(refreshTokenValue);

        // Save refresh token
        RefreshToken refreshToken = new RefreshToken(
            refreshTokenHash,
            user,
            LocalDateTime.now().plusSeconds(jwtService.getRefreshTokenExpirationMs() / 1000)
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

    /**
     * Validates if a client exists and is active
     * @param clientId The client ID to validate
     * @return The OAuthClient if valid
     * @throws AuthenticationException if client is not found or inactive
     */
    private OAuthClient validateClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new AuthenticationException("Client ID is required");
        }

        return oAuthClientRepository.findById(clientId)
            .filter(OAuthClient::isActive)
            .orElseThrow(() -> {
                logger.warn("Client not found or inactive: {}", clientId);
                return new AuthenticationException("Invalid client: " + clientId);
            });
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User updateUser(User user) {
        return userRepository.save(user);
    }
}
