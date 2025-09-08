package com.ia.idp.service;

import com.ia.idp.dto.ClientRequest;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.repository.OAuthClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class OAuthClientService {

    private static final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private OAuthClientRepository oAuthClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public OAuthClient createClient(ClientRequest request) {
        // Validate redirect URIs
        validateRedirectUris(request.getRedirectUris());
        
        // Validate grant types
        validateGrantTypes(request.getGrantTypes());

        // Generate client ID and secret
        String clientId = generateClientId();
        String clientSecret = generateClientSecret();
        String hashedSecret = passwordEncoder.encode(clientSecret);

        OAuthClient client = new OAuthClient();
        client.setClientId(clientId);
        client.setClientSecret(hashedSecret);
        client.setClientName(request.getClientName());
        client.setRedirectUris(request.getRedirectUris());
        client.setGrantTypes(request.getGrantTypes());
        client.setActive(request.isActive());
        client.setCreatedAt(LocalDateTime.now());

        OAuthClient savedClient = oAuthClientRepository.save(client);
        
        // Return the client with the plain text secret (only for creation response)
        savedClient.setClientSecret(clientSecret);
        return savedClient;
    }

    public List<OAuthClient> getAllClients() {
        return oAuthClientRepository.findAll();
    }

    public OAuthClient getClientById(String clientId) {
        return oAuthClientRepository.findByClientId(clientId).orElse(null);
    }

    public OAuthClient updateClient(String clientId, ClientRequest request) {
        OAuthClient existingClient = oAuthClientRepository.findByClientId(clientId).orElse(null);
        if (existingClient == null) {
            return null;
        }

        // Validate redirect URIs
        validateRedirectUris(request.getRedirectUris());
        
        // Validate grant types
        validateGrantTypes(request.getGrantTypes());

        existingClient.setClientName(request.getClientName());
        existingClient.setRedirectUris(request.getRedirectUris());
        existingClient.setGrantTypes(request.getGrantTypes());
        existingClient.setActive(request.isActive());

        return oAuthClientRepository.save(existingClient);
    }

    public boolean deleteClient(String clientId) {
        OAuthClient client = oAuthClientRepository.findByClientId(clientId).orElse(null);
        if (client == null) {
            return false;
        }

        oAuthClientRepository.delete(client);
        return true;
    }

    private String generateClientId() {
        return "client_" + UUID.randomUUID().toString().replace("-", "");
    }

    private String generateClientSecret() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private void validateRedirectUris(List<String> redirectUris) {
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalArgumentException("At least one redirect URI is required");
        }

        for (String uri : redirectUris) {
            if (uri == null || uri.trim().isEmpty()) {
                throw new IllegalArgumentException("Redirect URI cannot be empty");
            }
            
            // Basic URI validation
            if (!uri.startsWith("http://") && !uri.startsWith("https://")) {
                throw new IllegalArgumentException("Redirect URI must use HTTP or HTTPS protocol: " + uri);
            }
        }
    }

    private void validateGrantTypes(List<String> grantTypes) {
        if (grantTypes == null || grantTypes.isEmpty()) {
            throw new IllegalArgumentException("At least one grant type is required");
        }

        List<String> validGrantTypes = List.of("AUTHORIZATION_CODE", "CLIENT_CREDENTIALS", "REFRESH_TOKEN");
        
        for (String grantType : grantTypes) {
            if (!validGrantTypes.contains(grantType)) {
                throw new IllegalArgumentException("Invalid grant type: " + grantType + ". Valid types: " + validGrantTypes);
            }
        }
    }
}
