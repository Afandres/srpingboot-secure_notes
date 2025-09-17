package com.demo.secure_notes.auth;

import jakarta.servlet.http.*;
import org.springframework.security.core.*;
import org.springframework.security.web.authentication.*;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final UserRepository repo;

    public LoginSuccessHandler(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res,
            Authentication auth) throws IOException {
        repo.findByEmail(auth.getName()).ifPresent(u -> {
            u.setFailedAttempts(0);
            u.setLockUntil(null);
            repo.save(u);
        });
        res.setStatus(HttpServletResponse.SC_OK);
        res.getWriter().write("{\"status\":\"ok\"}");
    }
}