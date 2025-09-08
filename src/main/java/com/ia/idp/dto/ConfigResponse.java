package com.ia.idp.dto;

public class ConfigResponse {
    private String baseUrl;
    private String issuer;
    private String jwksUri;

    public ConfigResponse() {}

    public ConfigResponse(String baseUrl, String issuer, String jwksUri) {
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
