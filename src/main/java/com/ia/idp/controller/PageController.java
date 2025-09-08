package com.ia.idp.controller;

import com.ia.idp.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/auth/success")
    public String authSuccess(HttpServletRequest request, Model model) {
        // Get user information from session
        Object userObj = request.getSession().getAttribute("authenticated_user");
        if (userObj instanceof User) {
            User user = (User) userObj;
            model.addAttribute("user", user);
            
            // ✅ Retrieve the originally stored URL
            String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
            model.addAttribute("redirectUrl", redirectUrl);
            model.addAttribute("token", request.getSession().getAttribute("token"));
            model.addAttribute("refreshToken", request.getSession().getAttribute("refreshToken")); 

        }

        return "auth-success";
    }

    @GetMapping("/auth/error")
    public String authError() {
        return "auth-error";
    }
}
