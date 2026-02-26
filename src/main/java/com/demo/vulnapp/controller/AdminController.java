package com.demo.vulnapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin")
public class AdminController {
    
    @GetMapping("")
    public String adminPanel() {
        return "admin";
    }
    
    // VULN: Command injection example
    @PostMapping("/execute")
    public String executeCommand(@RequestParam String command) {
        // Vulnerable: Runtime.getRuntime().exec(command);
        return "admin";
    }
}