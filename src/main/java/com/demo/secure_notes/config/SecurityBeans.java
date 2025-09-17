package com.demo.secure_notes.config;

import com.demo.secure_notes.auth.UserRepository;
import org.springframework.context.annotation.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityBeans {

    @Bean
    PasswordEncoder passwordEncoder() {
        // cost >= 12 como pide el taller
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    UserDetailsService userDetailsService(UserRepository repo) {
        return username -> repo.findByEmail(username)
                .map(u -> User.withUsername(u.getEmail())
                        .password(u.getPasswordHash())
                        .authorities(u.getRoles().stream().map(Enum::name).toArray(String[]::new))
                        .accountLocked(false) // controlaremos lock manualmente
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
    }
}