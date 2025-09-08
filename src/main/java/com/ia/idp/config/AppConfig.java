package com.ia.idp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app")
public class AppConfig {

    private String baseUrl;
    private String frontendUrl;
    private boolean emailVerificationRequired;
    private boolean allowUnverifiedLogin;

    // Getters and Setters
    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getFrontendUrl() {
        return frontendUrl;
    }

    public void setFrontendUrl(String frontendUrl) {
        this.frontendUrl = frontendUrl;
    }

    public boolean isEmailVerificationRequired() {
        return emailVerificationRequired;
    }

    public void setEmailVerificationRequired(boolean emailVerificationRequired) {
        this.emailVerificationRequired = emailVerificationRequired;
    }

    public boolean isAllowUnverifiedLogin() {
        return allowUnverifiedLogin;
    }

    public void setAllowUnverifiedLogin(boolean allowUnverifiedLogin) {
        this.allowUnverifiedLogin = allowUnverifiedLogin;
    }
}
