package com.ia.idp.controller;

import com.ia.idp.dto.LoginRequest;
import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.RegisterRequest;
import com.ia.idp.entity.User;
import com.ia.idp.entity.UserRole;
import com.ia.idp.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.util.Collections;

@Controller
public class AdminAuthController {

    @Autowired
    private AuthenticationService authenticationService;
    private static final Logger logger = LoggerFactory.getLogger(AdminAuthController.class);
    @PostMapping("/admin/login")
    public void adminLogin(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) throws IOException {
        
        try {
            // Use the existing authentication service but bypass email verification for admin access
            AuthResponse authResponse = authenticationService.loginWithoutEmailVerification(loginRequest);
            
            // Check if user has admin role
            String userRole = authResponse.getUser().getRole();
            if (!"ROLE_ADMIN".equals(userRole)) {
                logger.warn("User {} attempted admin login without ROLE_ADMIN privileges", loginRequest.getEmail());
                response.sendRedirect("/login.html?error=insufficient_privileges");
                return;
            }
            
            // Create Spring Security authentication with actual user role
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(),
                null,
                Collections.singletonList(new SimpleGrantedAuthority(userRole))
            );
            
            // Set authentication details
            ((UsernamePasswordAuthenticationToken) authentication)
                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            
            // Set the authentication in the security context
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            
            // Save the security context to the session
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            
            // Store comprehensive user info and tokens in session for admin console
            session.setAttribute("user_id", authResponse.getUser().getId());
            session.setAttribute("user_email", authResponse.getUser().getEmail());
            session.setAttribute("user_name", authResponse.getUser().getFirstName() + " " + authResponse.getUser().getLastName());
            session.setAttribute("user_first_name", authResponse.getUser().getFirstName());
            session.setAttribute("user_last_name", authResponse.getUser().getLastName());
            session.setAttribute("user_provider", authResponse.getUser().getProvider());
            session.setAttribute("user_email_verified", authResponse.getUser().isEmailVerified());
            session.setAttribute("user_role", authResponse.getUser().getRole());
            
            // Store JWT tokens for API calls
            session.setAttribute("access_token", authResponse.getAccessToken());
            session.setAttribute("refresh_token", authResponse.getRefreshToken());
            session.setAttribute("token_type", authResponse.getTokenType());
            session.setAttribute("expires_in", authResponse.getExpiresIn());
            
            // Store login timestamp for session management
            session.setAttribute("login_timestamp", System.currentTimeMillis());
            session.setAttribute("authenticated", true);
            
            logger.info("Admin login successful for user: {} - Redirecting to console", loginRequest.getEmail());
            
            // Redirect to admin console
            response.sendRedirect("/ui/console/");
            
        } catch (Exception e) {
            // Redirect back to login with error
            logger.error("Admin login failed: " + e.getMessage());
            response.sendRedirect("/login.html?error=true");
        }
    }

    @PostMapping("/admin/register")
    @ResponseBody
    public void adminRegister(
            @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) throws IOException {
        
        try {
            // Register the user with ROLE_ADMIN
            authenticationService.register(registerRequest);
            
            // Update the user's role to ROLE_ADMIN after registration
            // This requires accessing the user repository to update the role
            User user = authenticationService.getUserByEmail(registerRequest.getEmail());
            if (user != null) {
                user.setRole(UserRole.ROLE_ADMIN);
                authenticationService.updateUser(user);
            }
            
            logger.info("Admin registration successful for user: {} - Redirecting to login", registerRequest.getEmail());
            
            // Redirect to login with success message
            response.sendRedirect("/login.html?registered=true");
            
        } catch (Exception e) {
            // Redirect back to login with error
            logger.error("Admin registration failed: " + e.getMessage());
            response.sendRedirect("/login.html?error=registration_failed");
        }
    }
}
