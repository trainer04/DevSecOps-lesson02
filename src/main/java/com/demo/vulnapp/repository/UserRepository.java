package com.demo.vulnapp.repository;

import com.demo.vulnapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // VULN: SQL Injection through @Query with concatenation
    @Query(value = "SELECT * FROM users WHERE username = :username", nativeQuery = true)
    User findByUsernameNative(@Param("username") String username);
    
    // Safe version for comparison
    User findByUsername(String username);
    
    // VULN: JPQL injection possible
    @Query("SELECT u FROM User u WHERE u.username LIKE %:search% OR u.email LIKE %:search%")
    List<User> searchUsers(@Param("search") String search);
}