package com.ia.idp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

public class ClientRequest {
    @NotBlank(message = "Client name is required")
    private String clientName;
    
    @NotEmpty(message = "At least one redirect URI is required")
    private List<String> redirectUris;
    
    @NotEmpty(message = "At least one grant type is required")
    private List<String> grantTypes;
    
    private boolean active = true;

    public ClientRequest() {}

    public ClientRequest(String clientName, List<String> redirectUris, List<String> grantTypes, boolean active) {
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.active = active;
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
}
