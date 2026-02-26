package com.demo.vulnapp.model;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;  // VULN: No encryption in transit mentioned
    
    // VULN: No validation annotations
}