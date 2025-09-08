package com.ia.idp.utils;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;

public class ResponseHandler {

    public static <T> ResponseEntity<T> responseSuccess(int statusCode, String message, T data) {
        Map<String, Object> response = new HashMap<>();
        response.put("resp_code", statusCode);
        response.put("resp_msg", message);
        response.put("data", data);
        return new ResponseEntity(response, HttpStatus.OK); // raw response to avoid type conflict
    }

    public static <T> ResponseEntity<T> responseError(int statusCode, String error, T data) {
        Map<String, Object> response = new HashMap<>();
        response.put("resp_code", statusCode);
        response.put("resp_msg", error);
        response.put("data", data);
        return new ResponseEntity(response, HttpStatus.OK);
    }

    public static <T> ResponseEntity<T> responseServerError(int statusCode, String error) {
        Map<String, Object> response = new HashMap<>();
        response.put("resp_code", statusCode);
        response.put("resp_msg",  error + "!");
        return new ResponseEntity(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
