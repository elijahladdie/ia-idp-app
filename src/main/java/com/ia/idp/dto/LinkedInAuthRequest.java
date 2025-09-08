package com.ia.idp.dto;

import jakarta.validation.constraints.NotBlank;

public class LinkedInAuthRequest {

    @NotBlank(message = "Authorization code is required")
    private String code;

    private String state;

    // Constructors
    public LinkedInAuthRequest() {}

    public LinkedInAuthRequest(String code, String state) {
        this.code = code;
        this.state = state;
    }

    // Getters and Setters
    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

}
