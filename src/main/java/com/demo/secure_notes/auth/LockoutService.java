package com.demo.secure_notes.auth;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
public class LockoutService {
    private final UserRepository repo;

    public LockoutService(UserRepository repo) {
        this.repo = repo;
    }

    public void registerFailedAttempt(String email) {
        repo.findByEmail(email).ifPresent(u -> {
            int attempts = u.getFailedAttempts() + 1;
            u.setFailedAttempts(attempts);
            if (attempts >= 5) {
                u.setLockUntil(Instant.now().plus(Duration.ofMinutes(15)));
            }
            repo.save(u);
        });
    }

    public void resetAttempts(String email) {
        repo.findByEmail(email).ifPresent(u -> {
            u.setFailedAttempts(0);
            u.setLockUntil(null);
            repo.save(u);
        });
    }

    public boolean isLocked(String email) {
        return repo.findByEmail(email)
                .map(u -> u.getLockUntil() != null && Instant.now().isBefore(u.getLockUntil()))
                .orElse(false);
    }
}
