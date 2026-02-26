package com.demo.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnappApplication {
    public static void main(String[] args) {
        // VULN: Information disclosure - debug mode enabled in production
        System.setProperty("debug", "true");
        
        // VULN: Disabling security manager
        System.setSecurityManager(null);
        
        SpringApplication.run(VulnappApplication.class, args);
    }
}