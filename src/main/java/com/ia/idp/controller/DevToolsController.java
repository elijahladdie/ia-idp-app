package com.ia.idp.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DevToolsController {

    @GetMapping("/.well-known/appspecific/com.chrome.devtools.json")
    public ResponseEntity<String> chromeDevTools() {
        // Return empty JSON to satisfy Chrome DevTools request
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}");
    }
}
