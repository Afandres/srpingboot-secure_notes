package com.demo.secure_notes.notes;

import com.demo.secure_notes.auth.UserRepository;
import com.demo.secure_notes.notes.dto.NoteCreateRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/notes")
public class NotesController {

    private final NoteRepository notes;
    private final UserRepository users;

    public NotesController(NoteRepository notes, UserRepository users) {
        this.notes = notes;
        this.users = users;
    }

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody NoteCreateRequest req, Authentication auth) {
        var owner = users.findByEmail(auth.getName()).orElseThrow();
        var note = Note.builder()
                .title(req.title())
                .content(req.content())
                .owner(owner)
                .build();
        notes.save(note);
        return ResponseEntity.ok(note);
    }

    @GetMapping
    public ResponseEntity<?> myNotes(Authentication auth) {
        var owner = users.findByEmail(auth.getName()).orElseThrow();
        return ResponseEntity.ok(notes.findByOwnerId(owner.getId()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> findOne(@PathVariable Long id, Authentication auth) {
        return guardOwner(id, auth)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).body("{\"error\":\"nota no encontrada o no es tuya\"}"));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @Valid @RequestBody NoteCreateRequest req,
            Authentication auth) {
        var noteOpt = guardOwner(id, auth);
        if (noteOpt.isEmpty())
            return ResponseEntity.status(404).body("{\"error\":\"nota no encontrada o no es tuya\"}");
        var note = noteOpt.get();
        note.setTitle(req.title());
        note.setContent(req.content());
        notes.save(note);
        return ResponseEntity.ok(note);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        var noteOpt = guardOwner(id, auth);
        if (noteOpt.isEmpty())
            return ResponseEntity.status(404).body("{\"error\":\"nota no encontrada o no es tuya\"}");
        notes.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private Optional<Note> guardOwner(Long id, Authentication auth) {
        var me = users.findByEmail(auth.getName()).orElseThrow();
        return notes.findById(id).filter(n -> n.getOwner().getId().equals(me.getId()));
    }
}