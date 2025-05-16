package ch.bbw.pr.tresorbackend.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * PasswordEncryptionService
 * Handles secure password hashing and verification using BCrypt
 * @author Peter Rutschmann
 */
@Service
public class PasswordEncryptionService {
    private final BCryptPasswordEncoder passwordEncoder;

    public PasswordEncryptionService() {
        // Using strength 12 for BCrypt (2^12 iterations)
        this.passwordEncoder = new BCryptPasswordEncoder(12);
    }

    /**
     * Hash a password using BCrypt
     * @param password The plain text password to hash
     * @return The hashed password
     * @throws IllegalArgumentException if password is null or empty
     */
    public String hashPassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        return passwordEncoder.encode(password);
    }

    /**
     * Verify if a plain text password matches a hashed password
     * @param plainPassword The plain text password to check
     * @param hashedPassword The hashed password to check against
     * @return true if the password matches, false otherwise
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}
