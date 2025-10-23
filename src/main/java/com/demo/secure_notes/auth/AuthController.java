package com.demo.secure_notes.auth;

import com.demo.secure_notes.security.JwtTokenProvider;
import jakarta.validation.Valid;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final LockoutService lockoutService;

    public AuthController(AuthenticationManager authManager,
            UserRepository userRepo,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider tokenProvider,
            LockoutService lockoutService) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.lockoutService = lockoutService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        if (userRepo.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Email ya registrado"));
        }

        User u = new User();
        u.setEmail(req.getEmail());
        u.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        u.setRoles(Boolean.TRUE.equals(req.getAdmin()) ? Set.of(Role.ROLE_ADMIN) : Set.of(Role.ROLE_USER));
        userRepo.save(u);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        if (lockoutService.isLocked(req.getEmail())) {
            return ResponseEntity.status(423).body(Map.of("error", "Usuario bloqueado temporalmente"));
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(req.getEmail(),
                req.getPassword());

        try {
            Authentication auth = authManager.authenticate(authToken);
            lockoutService.resetAttempts(req.getEmail());

            String jwt = tokenProvider.generateToken(auth);
            return ResponseEntity.ok(Map.of(
                    "accessToken", jwt,
                    "tokenType", "Bearer"));
        } catch (BadCredentialsException ex) {
            lockoutService.registerFailedAttempt(req.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Credenciales inválidas o usuario bloqueado"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No autenticado"));
        }

        return ResponseEntity.ok(Map.of(
                "email", auth.getName(),
                "roles", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()));
    }

}
