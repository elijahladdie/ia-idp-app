package com.ia.idp.controller;

import com.ia.idp.dto.AuthResponse;
import com.ia.idp.dto.ClientRequest;
import com.ia.idp.dto.ClientResponse;
import com.ia.idp.dto.ConfigRequest;
import com.ia.idp.dto.ConfigResponse;
import com.ia.idp.dto.ErrorResponse;
import com.ia.idp.dto.LoginRequest;
import com.ia.idp.dto.RegisterRequest;
import com.ia.idp.dto.SessionInfoResponse;
import com.ia.idp.dto.TokenResponse;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.entity.User;
import com.ia.idp.entity.UserRole;
import com.ia.idp.service.AuthenticationService;
import com.ia.idp.service.ConfigService;
import com.ia.idp.service.JwtService;
import com.ia.idp.service.OAuthClientService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ConfigService configService;

    @Autowired
    private OAuthClientService oAuthClientService;

    @PostMapping("/login")
    public void adminLogin(
            @RequestParam String email,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) throws IOException {

        try {
            // Create login request from form parameters
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setEmail(email);
            loginRequest.setPassword(password);
            
            // Use the existing authentication service but bypass email verification
            AuthResponse authResponse = authenticationService.loginWithoutEmailVerification(loginRequest);

            // Check if user has admin role
            String userRole = authResponse.getUser().getRole();
            if (!"ROLE_ADMIN".equals(userRole)) {
                logger.warn("User {} attempted admin login without ROLE_ADMIN privileges", email);
                response.sendRedirect("/login.html?error=insufficient_privileges");
                return;
            }

            // Create Spring Security authentication with actual user role
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    email,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority(userRole)));

            // Set authentication details
            ((UsernamePasswordAuthenticationToken) authentication)
                    .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set the authentication in the security context
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // Save the security context to the session
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            
            // Redirect to admin dashboard on success
            response.sendRedirect("/ui/console");

            session.setAttribute("user_id", authResponse.getUser().getId());
            session.setAttribute("user_email", authResponse.getUser().getEmail());
            session.setAttribute("user_name",
                    authResponse.getUser().getFirstName() + " " + authResponse.getUser().getLastName());
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

            logger.info("Admin login successful for user: {} - Redirecting to console", email);

            // Redirect to admin console
            response.sendRedirect("/ui/console");

        } catch (Exception e) {
            logger.error("Admin login failed: {}", e.getMessage());
            response.sendRedirect("/login.html?error=login_failed");
        }
    }

    @PostMapping("/register")
    public void adminRegister(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String firstName,
            @RequestParam String lastName,
            @RequestParam String confirmPassword,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) throws IOException {

        try {
            // Validate passwords match
            if (!password.equals(confirmPassword)) {
                response.sendRedirect("/login.html?error=password_mismatch");
                return;
            }
            
            // Create register request
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(email);
            registerRequest.setPassword(password);
            registerRequest.setFirstName(firstName);
            registerRequest.setLastName(lastName);
            // Set admin role
            User user = authenticationService.getUserByEmail(email);
            if (user != null) {
                user.setRole(UserRole.ROLE_ADMIN);
                authenticationService.updateUser(user);
            }

            logger.info("Admin registration successful for user: {} - Logging in", email);
            
            // Auto-login after registration
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    email,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
            
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            
            // Set user session attributes
            session.setAttribute("user_id", user.getId());
            session.setAttribute("user_email", user.getEmail());
            session.setAttribute("user_name", user.getFirstName() + " " + user.getLastName());
            session.setAttribute("user_first_name", user.getFirstName());
            session.setAttribute("user_last_name", user.getLastName());
            session.setAttribute("user_role", "ROLE_ADMIN");
            session.setAttribute("authenticated", true);
            
            // Redirect to dashboard
            response.sendRedirect("/ui/console");

        } catch (Exception e) {
            // Redirect back to login with error
            logger.error("Admin registration failed: " + e.getMessage());
            response.sendRedirect("/login.html?error=registration_failed");
        }
    }

    @GetMapping("/session/info")
    @PreAuthorize("hasRole('ADMIN')")
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
                    Collections.singletonList(userRole != null ? userRole : "ROLE_ADMIN"));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error getting session info: " + e.getMessage());
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/session/token")
    @PreAuthorize("hasRole('ADMIN')")
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

    @GetMapping("/config")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getConfig() {
        try {
            ConfigResponse config = configService.getCurrentConfig();
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            logger.error("Error fetching configuration: " + e.getMessage());
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Failed to fetch configuration: " + e.getMessage()));
        }
    }

    @PostMapping("/config")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateConfig(@Valid @RequestBody ConfigRequest request, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getDefaultMessage())
                    .collect(Collectors.joining(", "));
            return ResponseEntity.badRequest().body(new ErrorResponse(errorMessage));
        }

        try {
            ConfigResponse updatedConfig = configService.updateConfig(request);
            return ResponseEntity.ok(updatedConfig);
        } catch (Exception e) {
            logger.error("Error updating configuration: " + e.getMessage());
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Failed to update configuration: " + e.getMessage()));
        }
    }

    @PostMapping("/clients")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createClient(@Valid @RequestBody ClientRequest request, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getDefaultMessage())
                    .collect(Collectors.joining(", "));
            return ResponseEntity.badRequest().body(new ErrorResponse(errorMessage));
        }

        try {
            OAuthClient client = oAuthClientService.createClient(request);
            ClientResponse response = convertToResponse(client, true); // Include secret on creation
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            logger.error("Error creating OAuth client: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to create client: " + e.getMessage()));
        }
    }

    @GetMapping("/clients")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllClients() {
        try {
            List<OAuthClient> clients = oAuthClientService.getAllClients();
            List<ClientResponse> responses = clients.stream()
                    .map(client -> convertToResponse(client, false)) // Don't include secret
                    .collect(Collectors.toList());
            return ResponseEntity.ok(responses);
        } catch (Exception e) {
            logger.error("Error fetching OAuth clients: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to fetch clients: " + e.getMessage()));
        }
    }

    @GetMapping("/clients/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getClient(@PathVariable String clientId) {
        try {
            OAuthClient client = oAuthClientService.getClientById(clientId);
            if (client == null) {
                return ResponseEntity.notFound().build();
            }
            ClientResponse response = convertToResponse(client, false); // Don't include secret
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error fetching OAuth client: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to fetch client: " + e.getMessage()));
        }
    }

    @PutMapping("/clients/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateClient(@PathVariable String clientId,
            @Valid @RequestBody ClientRequest request,
            BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getDefaultMessage())
                    .collect(Collectors.joining(", "));
            return ResponseEntity.badRequest().body(new ErrorResponse(errorMessage));
        }

        try {
            OAuthClient client = oAuthClientService.updateClient(clientId, request);
            if (client == null) {
                return ResponseEntity.notFound().build();
            }
            ClientResponse response = convertToResponse(client, false); // Don't include secret
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error updating OAuth client: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to update client: " + e.getMessage()));
        }
    }

    @DeleteMapping("/clients/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteClient(@PathVariable String clientId) {
        try {
            boolean deleted = oAuthClientService.deleteClient(clientId);
            if (!deleted) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            logger.error("Error deleting OAuth client: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to delete client: " + e.getMessage()));
        }
    }

    private ClientResponse convertToResponse(OAuthClient client, boolean includeSecret) {
        return new ClientResponse(
                client.getClientId(),
                includeSecret ? client.getClientSecret() : null,
                client.getClientName(),
                client.getRedirectUris(),
                client.getGrantTypes(),
                client.isActive(),
                client.getCreatedAt());
    }
}
