package com.demo.vulnapp.controller;

import com.demo.vulnapp.model.LoginRequest;
import com.demo.vulnapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.sql.*;

@Controller
@RequestMapping("/auth")
public class AuthController {
    
    @Autowired
    private UserService userService;
    
    // VULN: Hardcoded admin credentials
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "Admin@123";
    
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
    
    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, 
                       HttpServletResponse response) throws SQLException {
        
        // VULN: No rate limiting
        // VULN: Verbose error messages
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();
        
        // VULN: SQL Injection in authentication
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/userdb", 
                "root", 
                "rootpassword"
            );
            
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" + username 
                       + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                // VULN: Session fixation - not regenerating session ID
                // VULN: Insecure cookie settings
                Cookie authCookie = new Cookie("auth_token", username + ":" + password);
                authCookie.setHttpOnly(false); // VULN: Should be true
                authCookie.setSecure(false);   // VULN: Should be true in production
                authCookie.setMaxAge(60 * 60 * 24 * 30); // 30 days - too long
                response.addCookie(authCookie);
                
                // VULN: Hardcoded redirect to admin if username contains 'admin'
                if (username.contains("admin")) {
                    return "redirect:/admin";
                }
                
                return "redirect:/dashboard";
            }
        } finally {
            if (conn != null) conn.close();
        }
        
        return "redirect:/auth/login?error=true";
    }
    
    @PostMapping("/reset-password")
    @ResponseBody
    public String resetPassword(@RequestParam String email, 
                               @RequestParam String newPassword) {
        
        // VULN: No email validation
        // VULN: No confirmation mechanism
        // VULN: Weak password reset logic
        
        // VULN: Command injection through email parameter
        try {
            String command = "echo 'Password reset for: " + email + "' | mail -s 'Password Reset' " + email;
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return "Password reset email sent (vulnerable implementation)";
    }
}