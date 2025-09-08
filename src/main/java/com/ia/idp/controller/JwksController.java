package com.ia.idp.controller;

import com.ia.idp.service.JwtService;
import com.ia.idp.utils.ResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private static final Logger logger = LoggerFactory.getLogger(JwksController.class);

    @Autowired
    private JwtService jwtService;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity getJwks() {
        try {
            logger.debug("JWKS endpoint accessed");
            Map<String, Object> jwks = jwtService.getJwksResponse();
            
            // For JWKS, we return the raw keys format as expected by JWT libraries
            return ResponseEntity.ok()
                    .header("Cache-Control", "public, max-age=3600")
                    .body(jwks);
        } catch (Exception e) {
            logger.error("Failed to generate JWKS response", e);
            return ResponseHandler.responseServerError(500, "Failed to retrieve JWKS");
        }
    }
}
