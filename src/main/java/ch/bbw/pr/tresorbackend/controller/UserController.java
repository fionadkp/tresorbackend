package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;
import ch.bbw.pr.tresorbackend.model.EmailAdress;
import ch.bbw.pr.tresorbackend.model.RegisterUser;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptionService;
import ch.bbw.pr.tresorbackend.service.PasswordValidationService;
import ch.bbw.pr.tresorbackend.service.UserService;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * UserController
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/users")
public class UserController {

   private final UserService userService;
   private final PasswordEncryptionService passwordService;
   private final PasswordValidationService passwordValidationService;
   private final ConfigProperties configProperties;
   private static final Logger logger = LoggerFactory.getLogger(UserController.class);

   @Autowired
   public UserController(ConfigProperties configProperties, 
                        UserService userService,
                        PasswordEncryptionService passwordService,
                        PasswordValidationService passwordValidationService) {
      this.configProperties = configProperties;
      this.userService = userService;
      this.passwordService = passwordService;
      this.passwordValidationService = passwordValidationService;
      logger.info("UserController initialized with CORS origin: {}", configProperties.getOrigin());
   }

   // build create User REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createUser(@Valid @RequestBody RegisterUser registerUser, BindingResult bindingResult) {
      logger.info("Creating new user with email: {}", registerUser.getEmail());

      // Input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         logger.error("Validation errors: {}", errors);

         JsonObject response = new JsonObject();
         JsonArray errorArray = new JsonArray();
         errors.forEach(errorArray::add);
         response.add("message", errorArray);
         return ResponseEntity.badRequest().body(new Gson().toJson(response));
      }

      // Password validation
      var validationResult = passwordValidationService.validatePassword(registerUser.getPassword());
      if (!validationResult.isValid()) {
         logger.error("Password validation failed: {}", validationResult.errors());
         JsonObject response = new JsonObject();
         JsonArray errorArray = new JsonArray();
         validationResult.errors().forEach(errorArray::add);
         response.add("message", errorArray);
         return ResponseEntity.badRequest().body(new Gson().toJson(response));
      }

      // Check if passwords match
      if (!registerUser.getPassword().equals(registerUser.getPasswordConfirmation())) {
         logger.error("Passwords do not match");
         JsonObject response = new JsonObject();
         response.addProperty("message", "Passwords do not match");
         return ResponseEntity.badRequest().body(new Gson().toJson(response));
      }

      // Check if email already exists
      if (userService.findByEmail(registerUser.getEmail()) != null) {
         logger.error("Email already exists: {}", registerUser.getEmail());
         JsonObject response = new JsonObject();
         response.addProperty("message", "Email already exists");
         return ResponseEntity.badRequest().body(new Gson().toJson(response));
      }

      // Create and save user
      try {
         User user = new User(
               null,
               registerUser.getFirstName(),
               registerUser.getLastName(),
               registerUser.getEmail(),
               passwordService.hashPassword(registerUser.getPassword())
         );

         User savedUser = userService.createUser(user);
         logger.info("User created successfully with ID: {}", savedUser.getId());

         JsonObject response = new JsonObject();
         response.addProperty("message", "User created successfully");
         return ResponseEntity.ok(new Gson().toJson(response));
      } catch (Exception e) {
         logger.error("Error creating user: {}", e.getMessage(), e);
         JsonObject response = new JsonObject();
         response.addProperty("message", "Error creating user");
         return ResponseEntity.internalServerError().body(new Gson().toJson(response));
      }
   }

   // build get user by id REST API
   // http://localhost:8080/api/users/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping("{id}")
   public ResponseEntity<User> getUserById(@PathVariable("id") Long userId) {
      User user = userService.getUserById(userId);
      return new ResponseEntity<>(user, HttpStatus.OK);
   }

   // Build Get All Users REST API
   // http://localhost:8080/api/users
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<User>> getAllUsers() {
      List<User> users = userService.getAllUsers();
      return new ResponseEntity<>(users, HttpStatus.OK);
   }

   // Build Update User REST API
   // http://localhost:8080/api/users/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<User> updateUser(@PathVariable("id") Long userId,
                                          @RequestBody User user) {
      user.setId(userId);
      User updatedUser = userService.updateUser(user);
      return new ResponseEntity<>(updatedUser, HttpStatus.OK);
   }

   // Build Delete User REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteUser(@PathVariable("id") Long userId) {
      userService.deleteUser(userId);
      return new ResponseEntity<>("User successfully deleted!", HttpStatus.OK);
   }


   // get user id by email
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<String> getUserIdByEmail(@RequestBody EmailAdress email, BindingResult bindingResult) {
      System.out.println("UserController.getUserIdByEmail: " + email);
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("UserController.createUser " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("UserController.createUser, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      System.out.println("UserController.getUserIdByEmail: input validation passed");

      User user = userService.findByEmail(email.getEmail());
      if (user == null) {
         System.out.println("UserController.getUserIdByEmail, no user found with email: " + email);
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "No user found with this email");
         String json = new Gson().toJson(obj);

         System.out.println("UserController.getUserIdByEmail, fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.getUserIdByEmail, user find by email");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", user.getId());
      String json = new Gson().toJson(obj);
      System.out.println("UserController.getUserIdByEmail " + json);
      return ResponseEntity.accepted().body(json);
   }

}
