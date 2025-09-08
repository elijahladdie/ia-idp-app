package com.ia.idp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Map /ui/console/** to static resources
        registry.addResourceHandler("/ui/console/**")
                .addResourceLocations("classpath:/static/")
                .setCachePeriod(3600); // Cache for 1 hour in production
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Redirect /ui/console to /ui/console/
        registry.addRedirectViewController("/ui/console", "/ui/console/");
        
        // Map /ui/console/ to index.html
        registry.addViewController("/ui/console/").setViewName("forward:/ui/console/index.html");
    }
}
