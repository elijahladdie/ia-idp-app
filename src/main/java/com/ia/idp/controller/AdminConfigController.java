package com.ia.idp.controller;

import com.ia.idp.dto.ConfigRequest;
import com.ia.idp.dto.ConfigResponse;
import com.ia.idp.dto.ErrorResponse;
import com.ia.idp.service.ConfigService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/config")
@PreAuthorize("hasRole('ADMIN')")
public class AdminConfigController {

    private static final Logger logger = LoggerFactory.getLogger(AdminConfigController.class);

    @Autowired
    private ConfigService configService;

    @GetMapping
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

    @PostMapping
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
}
