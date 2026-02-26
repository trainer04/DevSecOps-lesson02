package com.demo.vulnapp.service;

import com.demo.vulnapp.model.User;
import com.demo.vulnapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    // VULN: Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "WeakKey123";
    
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    
    public User saveUser(User user) {
        // VULN: No password complexity check
        // VULN: Storing plain text password (simulated)
        return userRepository.save(user);
    }
    
    public void deleteUserById(String id) {
        // VULN: SQL Injection - direct string concatenation
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/userdb", 
                "root", 
                "rootpassword"
            );
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("DELETE FROM users WHERE id = " + id);
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
    
    public List<User> searchUsersRawSql(String sql) {
        // VULN: Accepting raw SQL from user input
        List<User> users = new ArrayList<>();
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/userdb", 
                "root", 
                "rootpassword"
            );
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            while (rs.next()) {
                User user = new User();
                user.setId(rs.getLong("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                users.add(user);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        return users;
    }
    
    // VULN: Weak password hashing using MD5
    public String hashPasswordMD5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(password.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    // VULN: "Encryption" using XOR (very weak)
    public String encrypt(String input) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            output.append((char) (input.charAt(i) ^ ENCRYPTION_KEY.charAt(i % ENCRYPTION_KEY.length())));
        }
        return output.toString();
    }
    
    // VULN: Insecure random number generation
    public String generateToken() {
        return String.valueOf(System.currentTimeMillis()); // Predictable
    }
}