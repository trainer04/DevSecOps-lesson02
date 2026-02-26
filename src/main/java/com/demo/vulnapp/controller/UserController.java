package com.demo.vulnapp.controller;

import com.demo.vulnapp.model.User;
import com.demo.vulnapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.*;
import java.util.List;

@Controller
public class UserController {
    
    @Autowired
    private UserService userService;
    
    // VULN: Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "rootpassword";
    
    @GetMapping("/")
    public String home() {
        return "index";
    }
    
    @GetMapping("/users")
    public String listUsers(Model model) {
        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        
        // VULN: XSS - User input not sanitized before adding to model
        String search = ""; // This would come from user input
        model.addAttribute("search", search);
        
        return "users";
    }
    
    @PostMapping("/users/search")
    public String searchUsers(@RequestParam("query") String query, Model model, 
                              HttpServletRequest request) {
        
        // VULN: SQL Injection - concatenating user input directly into SQL query
        String sql = "SELECT * FROM users WHERE username LIKE '%" + query + "%' OR email LIKE '%" + query + "%'";
        
        List<User> users = userService.searchUsersRawSql(sql); // Dangerous method
        model.addAttribute("users", users);
        
        // VULN: Logging sensitive information
        System.out.println("Search query: " + query + " from IP: " + request.getRemoteAddr());
        
        return "users";
    }
    
    @GetMapping("/users/{id}")
    public String getUser(@PathVariable String id, Model model, HttpServletResponse response) 
            throws IOException, SQLException {
        
        // VULN: SQL Injection through path variable
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
            
            if (rs.next()) {
                User user = new User();
                user.setId(rs.getLong("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                model.addAttribute("user", user);
            }
        } finally {
            if (conn != null) conn.close();
        }
        
        return "user-detail";
    }
    
    @PostMapping("/users/create")
    public String createUser(@ModelAttribute User user, HttpServletRequest request) {
        
        // VULN: No input validation
        // VULN: Weak password hashing (MD5)
        String hashedPassword = userService.hashPasswordMD5(user.getPassword());
        user.setPassword(hashedPassword);
        
        // VULN: Storing password in session (information disclosure)
        request.getSession().setAttribute("userPassword", user.getPassword());
        
        userService.saveUser(user);
        
        // VULN: Open redirect
        String redirectUrl = request.getParameter("redirect");
        if (redirectUrl != null) {
            return "redirect:" + redirectUrl;
        }
        
        return "redirect:/users";
    }
    
    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable String id) {
        
        // VULN: No authorization check
        // VULN: SQL Injection
        userService.deleteUserById(id);
        
        return "redirect:/users";
    }
    
    @GetMapping("/debug")
    @ResponseBody
    public String debugEndpoint(HttpServletRequest request) {
        // VULN: Information disclosure - debug endpoint exposed
        StringBuilder debugInfo = new StringBuilder();
        debugInfo.append("Headers:\n");
        request.getHeaderNames().asIterator()
              .forEachRemaining(header -> debugInfo.append(header).append(": ")
                                  .append(request.getHeader(header)).append("\n"));
        
        debugInfo.append("\nParameters:\n");
        request.getParameterMap().forEach((key, values) -> 
            debugInfo.append(key).append("=").append(String.join(",", values)).append("\n"));
        
        return debugInfo.toString();
    }
}