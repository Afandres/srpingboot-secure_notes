package com.demo.secure_notes.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Component
public class LockoutFilter implements Filter {

    private final UserRepository repo;
    private final ObjectMapper mapper = new ObjectMapper();

    public LockoutFilter(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Solo interceptamos el login API
        if ("/auth/login".equals(req.getServletPath()) && "POST".equalsIgnoreCase(req.getMethod())) {
            // ⚠️ No leemos el cuerpo (InputStream), solo verificamos por parámetro opcional
            String email = req.getParameter("email");
            if (email != null) {
                var userOpt = repo.findByEmail(email);
                if (userOpt.isPresent()) {
                    var u = userOpt.get();
                    if (u.getLockUntil() != null && Instant.now().isBefore(u.getLockUntil())) {
                        res.setStatus(423);
                        res.setContentType("application/json");
                        res.getWriter().write("{\"error\":\"usuario bloqueado temporalmente\"}");
                        return;
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }
}
