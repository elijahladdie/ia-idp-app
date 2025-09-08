package com.ia.idp.controller;

import com.ia.idp.utils.ResponseHandler;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
public class HealthController {

    @GetMapping("/health")
    public ResponseEntity health() {
        Map<String, Object> healthData = Map.of(
            "status", "UP",
            "timestamp", LocalDateTime.now(),
            "service", "Identity Provider",
            "version", "1.0.0"
        );
        return ResponseHandler.responseSuccess(200, "Service is healthy", healthData);
    }
}
