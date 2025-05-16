package ch.bbw.pr.tresorbackend.service;

import ch.bbw.pr.tresorbackend.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service for handling user authentication
 */
@Service
public class AuthenticationService {
    private final PasswordEncryptionService passwordEncryptionService;
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    @Autowired
    public AuthenticationService(PasswordEncryptionService passwordEncryptionService) {
        this.passwordEncryptionService = passwordEncryptionService;
    }

    /**
     * Authenticate a user
     * @param username the username
     * @param password the plain text password
     * @param storedHash the stored password hash
     * @return true if authentication is successful
     * @throws AuthenticationException if authentication fails
     */
    public boolean authenticate(String username, String password, String storedHash) 
            throws AuthenticationException {
        if (username == null || password == null || storedHash == null) {
            throw new AuthenticationException("Invalid credentials");
        }

        boolean isValid = passwordEncryptionService.verifyPassword(password, storedHash);
        
        if (!isValid) {
            throw new AuthenticationException("Invalid username or password");
        }
        
        return true;
    }
} 