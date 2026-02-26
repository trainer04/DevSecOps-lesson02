package com.demo.vulnapp.model;

import lombok.Data;
import javax.persistence.*;

@Entity
@Table(name = "users")
@Data
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String username;
    
    @Column(nullable = false)
    private String password;  // VULN: Plain text password in model
    
    @Column(nullable = false, unique = true)
    private String email;
    
    @Column
    private String role = "USER";  // VULN: Default role
    
    // VULN: Sensitive data in toString()
    @Override
    public String toString() {
        return String.format("User[id=%d, username='%s', password='%s', email='%s']", 
                           id, username, password, email);
    }
}