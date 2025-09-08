package com.ia.idp.controller;

import com.ia.idp.dto.ClientRequest;
import com.ia.idp.dto.ClientResponse;
import com.ia.idp.dto.ErrorResponse;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.service.OAuthClientService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/clients")
@PreAuthorize("hasRole('ADMIN')")
public class AdminClientController {

    private static final Logger logger = LoggerFactory.getLogger(AdminClientController.class);

    @Autowired
    private OAuthClientService oAuthClientService;

    @PostMapping
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

    @GetMapping
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

    @GetMapping("/{clientId}")
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

    @PutMapping("/{clientId}")
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

    @DeleteMapping("/{clientId}")
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
            client.getCreatedAt()
        );
    }
}
