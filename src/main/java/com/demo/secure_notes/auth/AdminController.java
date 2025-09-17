package com.demo.secure_notes.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {
    private final UserRepository repo;

    public AdminController(UserRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/users")
    public ResponseEntity<?> users() {
        return ResponseEntity.ok(repo.findAll());
    }
}