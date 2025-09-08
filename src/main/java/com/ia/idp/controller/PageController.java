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
            
            model.addAttribute("redirectUrl", request.getParameter("redirectUrl"));
        }

        return "auth-success";
    }

    @GetMapping("/auth/error")
    public String authError() {
        return "auth-error";
    }
}
