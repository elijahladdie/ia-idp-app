package com.ia.idp.service;

import com.ia.idp.config.JwtConfig;
import com.ia.idp.dto.ConfigRequest;
import com.ia.idp.dto.ConfigResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class ConfigService {

    @Autowired
    private JwtConfig jwtConfig;

    @Autowired
    private ConfigurableEnvironment environment;

    @Value("${app.base-url}")
    private String baseUrl;

    public ConfigResponse getCurrentConfig() {
        String jwksUri = baseUrl + "/.well-known/jwks.json";
        
        return new ConfigResponse(
            baseUrl,
            jwtConfig.getIssuer(),
            jwksUri
        );
    }

    public ConfigResponse updateConfig(ConfigRequest request) {
        // Create a new property source with updated values
        Map<String, Object> updatedProperties = new HashMap<>();
        updatedProperties.put("app.base-url", request.getBaseUrl());
        updatedProperties.put("jwt.issuer", request.getIssuer());
        
        // Add the property source to the environment
        MapPropertySource updatedPropertySource = new MapPropertySource("updatedConfig", updatedProperties);
        environment.getPropertySources().addFirst(updatedPropertySource);
        
        // Update the base URL for this instance
        this.baseUrl = request.getBaseUrl();
        
        // Return the updated configuration
        return new ConfigResponse(
            request.getBaseUrl(),
            request.getIssuer(),
            request.getJwksUri()
        );
    }
}
