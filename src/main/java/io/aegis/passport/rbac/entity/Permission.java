package io.aegis.passport.rbac.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * An atomic, checkable capability such as {@code user:write} or
 * {@code client:delete}. The catalog is seeded at startup and grouped by
 * {@link #category} for display in the admin console.
 */
@Entity
@Table(name = "permissions")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** e.g. {@code user:read}, {@code system:config:edit}. */
    @Column(unique = true, nullable = false, length = 100)
    private String code;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    /** Grouping label, e.g. {@code user}, {@code client}, {@code system}. */
    @Column(length = 50)
    private String category;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
}
