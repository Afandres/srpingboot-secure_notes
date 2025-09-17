package com.demo.secure_notes.notes.dto;

import jakarta.validation.constraints.*;

public record NoteCreateRequest(
        @NotBlank String title,
        @NotBlank String content) {
}