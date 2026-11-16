package io.aegis.passport.organization.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity @Table(name="organizations")
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class Organization {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
    @Column(nullable=false,unique=true,length=100) private String name;
    @Column(length=255) private String description;
    @CreationTimestamp @Column(nullable=false,updatable=false) private Instant createdAt;
    @UpdateTimestamp @Column(nullable=false) private Instant updatedAt;
}
