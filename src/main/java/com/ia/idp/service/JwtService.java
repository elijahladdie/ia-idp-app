package com.ia.idp.service;

import com.ia.idp.config.JwtConfig;
import com.ia.idp.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Autowired
    private JwtConfig jwtConfig;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            generateKeys();
        } catch (Exception e) {
            logger.error("Failed to generate JWT keys", e);
            throw new RuntimeException("Failed to initialize JWT service", e);
        }
    }

    private void generateKeys() throws NoSuchAlgorithmException {
        // Generate RSA key pair with 2048-bit key size for security
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();

        logger.info("JWT RSA key pair generated successfully (2048-bit)");
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(jwtConfig.getAccessToken().getExpiration());

        return Jwts.builder()
                .header()
                    .keyId(jwtConfig.getKeyId())
                    .type("JWT")
                    .and()
                .subject(user.getId().toString())
                .issuer(jwtConfig.getIssuer())
                .audience().add(user.getProvider().name()).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .claim("email", user.getEmail())
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .claim("emailVerified", user.getEmailVerified())
                .claim("provider", user.getProvider().name())
                .claim("role", user.getRole().name())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public Claims validateAndParseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            throw new RuntimeException("Invalid token", e);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public String getUserIdFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getSubject();
    }

    public String getEmailFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("email", String.class);
    }

    public String getRoleFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("role", String.class);
    }

    public LocalDateTime getExpirationFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return LocalDateTime.ofInstant(claims.getExpiration().toInstant(), ZoneId.systemDefault());
    }

    public Map<String, Object> getJwksResponse() {
        Map<String, Object> jwks = new HashMap<>();
        Map<String, Object> key = new HashMap<>();

        key.put("kty", "RSA");
        key.put("use", "sig");
        key.put("kid", jwtConfig.getKeyId());
        key.put("alg", "RS256");
        key.put("n", getModulus());
        key.put("e", getExponent());

        jwks.put("keys", new Object[]{key});
        return jwks;
    }

    private String getModulus() {
        try {
            java.security.interfaces.RSAPublicKey rsaPublicKey = 
                (java.security.interfaces.RSAPublicKey) publicKey;
            byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();
            
            // Remove leading zero byte if present
            if (modulusBytes[0] == 0 && modulusBytes.length > 1) {
                byte[] temp = new byte[modulusBytes.length - 1];
                System.arraycopy(modulusBytes, 1, temp, 0, temp.length);
                modulusBytes = temp;
            }
            
            return Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
        } catch (Exception e) {
            logger.error("Error extracting modulus from public key", e);
            throw new RuntimeException("Failed to extract modulus", e);
        }
    }

    private String getExponent() {
        try {
            java.security.interfaces.RSAPublicKey rsaPublicKey = 
                (java.security.interfaces.RSAPublicKey) publicKey;
            byte[] exponentBytes = rsaPublicKey.getPublicExponent().toByteArray();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);
        } catch (Exception e) {
            logger.error("Error extracting exponent from public key", e);
            throw new RuntimeException("Failed to extract exponent", e);
        }
    }

    public long getAccessTokenExpirationMs() {
        return jwtConfig.getAccessToken().getExpiration();
    }

    public long getRefreshTokenExpirationMs() {
        return jwtConfig.getRefreshToken().getExpiration();
    }
}
