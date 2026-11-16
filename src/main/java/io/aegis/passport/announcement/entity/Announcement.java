package io.aegis.passport.announcement.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/** A system announcement shown to users, optionally time-bounded. */
@Entity
@Table(name = "announcements")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Announcement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    /** {@code info}, {@code success}, {@code warning} or {@code error}. */
    @Column(nullable = false, length = 20)
    @Builder.Default
    private String level = "info";

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "start_time")
    private Instant startTime;

    @Column(name = "end_time")
    private Instant endTime;

    @Column(name = "created_by", nullable = false, length = 100)
    private String createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Audience targeting, stored as a comma-separated list of OAuth {@code client_id}s.
     * {@code null} / empty means global (visible to every client / all users).
     * Hidden from the wire: callers see the derived {@link #getTargets()} list instead.
     */
    @JsonIgnore
    @Column(name = "target_clients", length = 1000)
    private String targetClients;

    /** OAuth client ids this announcement is restricted to; empty = global. */
    public List<String> getTargets() {
        if (targetClients == null || targetClients.isBlank()) return List.of();
        return Arrays.stream(targetClients.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /** Sets the target client ids. A null / empty list clears targeting (global). */
    public void setTargets(List<String> targets) {
        if (targets == null || targets.isEmpty()) {
            this.targetClients = null;
        } else {
            this.targetClients = String.join(",", targets.stream()
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList());
        }
    }
}
