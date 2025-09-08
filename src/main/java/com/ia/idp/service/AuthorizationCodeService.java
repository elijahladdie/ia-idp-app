package com.ia.idp.service;

import com.ia.idp.entity.AuthorizationCode;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.entity.User;
import com.ia.idp.repository.AuthorizationCodeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
@Transactional
public class AuthorizationCodeService {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeService.class);
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int CODE_EXPIRY_MINUTES = 10; // OAuth 2.0 recommendation: short-lived codes

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    public AuthorizationCode generateAuthorizationCode(User user, OAuthClient client, String redirectUri, 
                                                     String scope, String state, String codeChallenge, 
                                                     String codeChallengeMethod) {
        // Generate secure authorization code
        String code = generateSecureCode();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(CODE_EXPIRY_MINUTES);

        AuthorizationCode authCode = new AuthorizationCode(
            code, user, client, redirectUri, scope, state, expiresAt
        );
        
        // Set PKCE parameters if provided
        if (codeChallenge != null && !codeChallenge.isEmpty()) {
            authCode.setCodeChallenge(codeChallenge);
            authCode.setCodeChallengeMethod(codeChallengeMethod != null ? codeChallengeMethod : "plain");
        }

        AuthorizationCode savedCode = authorizationCodeRepository.save(authCode);
        logger.info("Generated authorization code for user {} and client {}", user.getId(), client.getClientId());
        
        return savedCode;
    }

    public Optional<AuthorizationCode> validateAndConsumeCode(String code) {
        Optional<AuthorizationCode> authCodeOpt = authorizationCodeRepository.findValidCode(code, LocalDateTime.now());
        
        if (authCodeOpt.isPresent()) {
            AuthorizationCode authCode = authCodeOpt.get();
            
            // Mark code as used (single-use)
            authCode.markAsUsed();
            authorizationCodeRepository.save(authCode);
            
            logger.info("Authorization code consumed for user {} and client {}", 
                       authCode.getUser().getId(), authCode.getClient().getClientId());
            
            return Optional.of(authCode);
        }
        
        logger.warn("Invalid or expired authorization code: {}", code);
        return Optional.empty();
    }

    public void cleanupExpiredCodes() {
        authorizationCodeRepository.deleteExpiredCodes(LocalDateTime.now());
        logger.info("Cleaned up expired authorization codes");
    }

    public void revokeUserCodes(User user) {
        authorizationCodeRepository.deleteByUser(user);
        logger.info("Revoked all authorization codes for user {}", user.getId());
    }

    public void revokeClientCodes(OAuthClient client) {
        authorizationCodeRepository.deleteByClient(client);
        logger.info("Revoked all authorization codes for client {}", client.getClientId());
    }

    private String generateSecureCode() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public boolean validatePKCE(AuthorizationCode authCode, String codeVerifier) {
        if (authCode.getCodeChallenge() == null) {
            // No PKCE challenge was provided during authorization
            return codeVerifier == null;
        }

        if (codeVerifier == null) {
            logger.warn("Code verifier required but not provided");
            return false;
        }

        String method = authCode.getCodeChallengeMethod();
        if ("plain".equals(method)) {
            return authCode.getCodeChallenge().equals(codeVerifier);
        } else if ("S256".equals(method)) {
            // SHA256 challenge method
            try {
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                String computedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return authCode.getCodeChallenge().equals(computedChallenge);
            } catch (Exception e) {
                logger.error("Error validating PKCE S256 challenge", e);
                return false;
            }
        }

        logger.warn("Unsupported PKCE challenge method: {}", method);
        return false;
    }
}
