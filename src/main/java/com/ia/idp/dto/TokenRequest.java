package com.ia.idp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class TokenRequest {

    @NotBlank(message = "grant_type is required")
    @Pattern(regexp = "authorization_code|refresh_token|client_credentials", 
             message = "grant_type must be 'authorization_code', 'refresh_token', or 'client_credentials'")
    private String grantType;

    @NotBlank(message = "client_id is required")
    private String clientId;

    private String clientSecret;

    // For authorization_code grant
    private String code;
    private String redirectUri;
    private String codeVerifier; // PKCE

    // For refresh_token grant
    private String refreshToken;

    // For all grants
    private String scope;

    // Constructors
    public TokenRequest() {}

    // Getters and Setters
    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
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

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public void setCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
