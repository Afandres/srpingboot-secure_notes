package com.demo.secure_notes.auth.dto;

import jakarta.validation.constraints.*;

public record RegisterRequest(
        @Email @NotBlank String email,
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{10,}$", message = "Mín. 10 chars, 1 mayús, 1 minús, 1 dígito") String password,
        boolean admin) {
}