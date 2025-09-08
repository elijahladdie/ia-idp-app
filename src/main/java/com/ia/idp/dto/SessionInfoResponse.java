package com.ia.idp.dto;

import java.util.List;

public class SessionInfoResponse {
    private String user_name;
    private String user_email;
    private List<String> roles;

    public SessionInfoResponse() {}

    public SessionInfoResponse(String user_name, String user_email, List<String> roles) {
        this.user_name = user_name;
        this.user_email = user_email;
        this.roles = roles;
    }

    public String getUser_name() {
        return user_name;
    }

    public void setUser_name(String user_name) {
        this.user_name = user_name;
    }

    public String getUser_email() {
        return user_email;
    }

    public void setUser_email(String user_email) {
        this.user_email = user_email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
