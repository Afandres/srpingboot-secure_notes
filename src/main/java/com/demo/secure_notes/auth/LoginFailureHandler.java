package com.demo.secure_notes.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserRepository repo;

    public LoginFailureHandler(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest req,
                                        HttpServletResponse res,
                                        AuthenticationException ex) throws IOException {
        String email = req.getParameter("username");
        repo.findByEmail(email).ifPresent(u -> {
            int attempts = u.getFailedAttempts() + 1;
            u.setFailedAttempts(attempts);
            if (attempts >= 5) {
                u.setLockUntil(Instant.now().plus(Duration.ofMinutes(15)));
            }
            repo.save(u);
        });
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.getWriter().write("{\"error\":\"credenciales inválidas o usuario bloqueado\"}");
    }
}
