package com.demo.secure_notes.auth;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.time.Instant;

@Component
public class LockoutFilter implements Filter {
    private final UserRepository repo;

    public LockoutFilter(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if ("/login".equals(req.getServletPath()) && "POST".equalsIgnoreCase(req.getMethod())) {
            String email = req.getParameter("username");
            if (email != null) {
                var userOpt = repo.findByEmail(email);
                if (userOpt.isPresent()) {
                    var u = userOpt.get();
                    if (u.getLockUntil() != null && Instant.now().isBefore(u.getLockUntil())) {
                        res.setStatus(423); // 423
                        res.getWriter().write("{\"error\":\"usuario bloqueado temporalmente\"}");
                        return;
                    }
                }
            }
        }
        chain.doFilter(request, response);
    }
}