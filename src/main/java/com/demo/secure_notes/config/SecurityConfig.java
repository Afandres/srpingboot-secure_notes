package com.demo.secure_notes.config;

import com.demo.secure_notes.auth.LockoutFilter;
import com.demo.secure_notes.auth.LoginFailureHandler;
import com.demo.secure_notes.auth.LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
            LockoutFilter lockoutFilter,
            LoginSuccessHandler successHandler,
            LoginFailureHandler failureHandler) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Desactivado para pruebas con Postman/cURL
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                // Desactiva el formulario HTML y usa solo login por API
                .formLogin(form -> form
                        .loginProcessingUrl("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll())
                .logout(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .logout(Customizer.withDefaults())
                .addFilterBefore(lockoutFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).preload(true))
                        .referrerPolicy(r -> r.policy(
                                org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .contentTypeOptions(cto -> {
                        }));

        return http.build();
    }
}
