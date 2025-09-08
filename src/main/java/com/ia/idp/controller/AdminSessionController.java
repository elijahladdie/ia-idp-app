package com.ia.idp.controller;

import com.ia.idp.dto.SessionInfoResponse;
import com.ia.idp.dto.TokenResponse;
import com.ia.idp.entity.User;
import com.ia.idp.service.AuthenticationService;
import com.ia.idp.service.JwtService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@RestController
@RequestMapping("/admin/session")
@PreAuthorize("hasRole('ADMIN')")
public class AdminSessionController {

    private static final Logger logger = LoggerFactory.getLogger(AdminSessionController.class);

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private JwtService jwtService;

    @GetMapping("/info")
    public ResponseEntity<SessionInfoResponse> getSessionInfo(HttpSession session) {
        try {
            String userEmail = (String) session.getAttribute("user_email");
            String userName = (String) session.getAttribute("user_name");
            String userRole = (String) session.getAttribute("user_role");

            if (userEmail == null) {
                return ResponseEntity.status(401).build();
            }

            SessionInfoResponse response = new SessionInfoResponse(
                userName != null ? userName : "Unknown User",
                userEmail,
                Collections.singletonList(userRole != null ? userRole : "ROLE_ADMIN")
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error getting session info: " + e.getMessage());
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/token")
    public ResponseEntity<TokenResponse> getApiToken(HttpSession session) {
        try {
            String userEmail = (String) session.getAttribute("user_email");
            
            if (userEmail == null) {
                return ResponseEntity.status(401).build();
            }

            // Get user from database to generate fresh token
            User user = authenticationService.getUserByEmail(userEmail);
            if (user == null) {
                return ResponseEntity.status(401).build();
            }

            // Generate new access token
            String accessToken = jwtService.generateAccessToken(user);
            long expiresIn = jwtService.getAccessTokenExpirationMs() / 1000;

            TokenResponse response = new TokenResponse(accessToken, expiresIn);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error generating API token: " + e.getMessage());
            return ResponseEntity.status(500).build();
        }
    }
}
