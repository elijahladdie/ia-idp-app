package com.ia.idp.dto;

import jakarta.validation.constraints.NotBlank;

public class ConfigRequest {
    @NotBlank(message = "Base URL is required")
    private String baseUrl;
    
    @NotBlank(message = "Issuer is required")
    private String issuer;
    
    @NotBlank(message = "JWKS URI is required")
    private String jwksUri;

    public ConfigRequest() {}

    public ConfigRequest(String baseUrl, String issuer, String jwksUri) {
        this.baseUrl = baseUrl;
        this.issuer = issuer;
        this.jwksUri = jwksUri;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }
}
