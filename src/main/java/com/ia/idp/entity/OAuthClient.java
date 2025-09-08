package com.ia.idp.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "oauth_clients", indexes = {
    @Index(name = "idx_oauth_client_id", columnList = "client_id", unique = true)
})
public class OAuthClient {

    @Id
    @Column(name = "client_id", length = 255)
    @NotBlank
    @Size(max = 255)
    private String clientId;

    @Column(name = "client_secret_hash", nullable = false)
    @NotBlank
    private String clientSecretHash;

    @Column(name = "client_name", nullable = false)
    @NotBlank
    @Size(max = 100)
    private String clientName;

    @ElementCollection
    @CollectionTable(name = "oauth_client_redirect_uris", 
                    joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private List<String> redirectUris;

    @ElementCollection
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "oauth_client_grant_types", 
                    joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type")
    private List<GrantType> allowedGrantTypes;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // Constructors
    public OAuthClient() {}

    public OAuthClient(String clientId, String clientSecretHash, String clientName) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.clientName = clientName;
    }
    
    @PrePersist
    public void generateClientId() {
        if (this.clientId == null || this.clientId.isBlank()) {
            this.clientId = "client-" + java.util.UUID.randomUUID();
        }
    }
    // Getters and Setters
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public void setClientSecretHash(String clientSecretHash) {
        this.clientSecretHash = clientSecretHash;
    }

    public String getClientSecret() {
        return clientSecretHash;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecretHash = clientSecret;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public List<GrantType> getAllowedGrantTypes() {
        return allowedGrantTypes;
    }

    public void setAllowedGrantTypes(List<GrantType> allowedGrantTypes) {
        this.allowedGrantTypes = allowedGrantTypes;
    }

    public List<String> getGrantTypes() {
        if (allowedGrantTypes == null) return null;
        return allowedGrantTypes.stream().map(Enum::name).toList();
    }

    public void setGrantTypes(List<String> grantTypes) {
        if (grantTypes == null) {
            this.allowedGrantTypes = null;
        } else {
            this.allowedGrantTypes = grantTypes.stream()
                .map(GrantType::valueOf)
                .toList();
        }
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public boolean isActive() {
        return isActive != null ? isActive : false;
    }

    public void setActive(boolean active) {
        this.isActive = active;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    // Utility methods
    public boolean isRedirectUriValid(String redirectUri) {
        return redirectUris != null && redirectUris.contains(redirectUri);
    }

    public boolean isGrantTypeAllowed(GrantType grantType) {
        return allowedGrantTypes != null && allowedGrantTypes.contains(grantType);
    }

    public enum GrantType {
        AUTHORIZATION_CODE,
        REFRESH_TOKEN,
        CLIENT_CREDENTIALS
    }
}
