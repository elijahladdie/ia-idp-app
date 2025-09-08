package com.ia.idp.dto;

import java.time.LocalDateTime;
import java.util.List;

public class ClientResponse {
    private String clientId;
    private String clientSecret; // Only returned on creation
    private String clientName;
    private List<String> redirectUris;
    private List<String> grantTypes;
    private boolean active;
    private LocalDateTime createdAt;

    public ClientResponse() {}

    public ClientResponse(String clientId, String clientSecret, String clientName, 
                         List<String> redirectUris, List<String> grantTypes, 
                         boolean active, LocalDateTime createdAt) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.active = active;
        this.createdAt = createdAt;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
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

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
