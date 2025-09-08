package com.ia.idp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class AuthorizeRequest {

    @NotBlank(message = "client_id is required")
    private String clientId;

    @NotBlank(message = "redirect_uri is required")
    private String redirectUri;

    @NotBlank(message = "response_type is required")
    @Pattern(regexp = "code", message = "Only 'code' response_type is supported")
    private String responseType;

    private String scope;

    private String state;

    // PKCE parameters
    private String codeChallenge;

    @Pattern(regexp = "plain|S256", message = "code_challenge_method must be 'plain' or 'S256'")
    private String codeChallengeMethod;

    // Constructors
    public AuthorizeRequest() {}

    public AuthorizeRequest(String clientId, String redirectUri, String responseType) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.responseType = responseType;
    }

    // Getters and Setters
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }
}
