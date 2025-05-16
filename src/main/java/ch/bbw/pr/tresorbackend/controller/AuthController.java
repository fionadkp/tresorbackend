package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.dto.LoginRequest;
import ch.bbw.pr.tresorbackend.dto.LoginResponse;
import ch.bbw.pr.tresorbackend.exception.AuthenticationException;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.AuthenticationService;
import ch.bbw.pr.tresorbackend.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling authentication endpoints
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "${CROSS_ORIGIN}", 
             allowedHeaders = "*", 
             methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class AuthController {
    private final AuthenticationService authenticationService;
    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    public AuthController(AuthenticationService authenticationService, UserService userService) {
        this.authenticationService = authenticationService;
        this.userService = userService;
    }

    /**
     * Handle login requests
     * @param request the login request containing username and password
     * @return ResponseEntity with login response
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        try {
            logger.info("Login attempt for user: {}", request.username());
            
            // Validate request
            if (request.username() == null || request.password() == null) {
                logger.error("Login failed: Missing username or password");
                return ResponseEntity.ok(new LoginResponse("Username and password are required", false));
            }

            // Find user by email (which is used as username)
            User user = userService.findByEmail(request.username());
            if (user == null) {
                logger.error("Login failed: No user found with email: {}", request.username());
                return ResponseEntity.ok(new LoginResponse("Invalid username or password", false));
            }
            logger.debug("User found with email: {}", request.username());

            // Authenticate using the stored password hash
            boolean isAuthenticated = authenticationService.authenticate(
                request.username(),
                request.password(),
                user.getPassword() // Get the actual stored hash
            );
            
            if (!isAuthenticated) {
                logger.error("Login failed: Invalid password for user: {}", request.username());
                return ResponseEntity.ok(new LoginResponse("Invalid username or password", false));
            }
            
            logger.info("Login successful for user: {}", request.username());
            return ResponseEntity.ok(new LoginResponse("Login successful", true));
        } catch (AuthenticationException e) {
            logger.error("Authentication failed for user {}: {}", request.username(), e.getMessage());
            return ResponseEntity.ok(new LoginResponse(e.getMessage(), false));
        } catch (Exception e) {
            logger.error("Unexpected error during login for user {}: {}", request.username(), e.getMessage(), e);
            return ResponseEntity.ok(new LoginResponse("An error occurred during login", false));
        }
    }
} 