package com.ia.idp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ia.idp.utils.ResponseHandler;


@RestController
public class RootController {
    @GetMapping("/")
    public ResponseEntity<?> index() {
        return ResponseHandler.responseSuccess(200, "API is running. Go to /oauth2/authorization/microsoft to login.",
                null);
    }
}