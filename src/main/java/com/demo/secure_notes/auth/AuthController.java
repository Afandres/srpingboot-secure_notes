package com.demo.secure_notes.auth;

import com.demo.secure_notes.auth.dto.RegisterRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        if (repo.findByEmail(req.email()).isPresent()) {
            return ResponseEntity.badRequest().body("{\"error\":\"email ya registrado\"}");
        }
        var roles = req.admin() ? Set.of(Role.ROLE_USER, Role.ROLE_ADMIN) : Set.of(Role.ROLE_USER);
        var u = User.builder()
                .email(req.email())
                .passwordHash(encoder.encode(req.password()))
                .roles(roles)
                .failedAttempts(0)
                .build();
        repo.save(u);
        return ResponseEntity.ok().body("{\"status\":\"registrado\"}");
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        if (auth == null)
            return ResponseEntity.status(401).build();
        return ResponseEntity.ok(new Object() {
            public final String email = auth.getName();
            public final Object roles = auth.getAuthorities();
        });
    }
}