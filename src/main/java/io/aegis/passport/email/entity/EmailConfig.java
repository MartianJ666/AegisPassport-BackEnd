package io.aegis.passport.email.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

/** SMTP settings used for sending verification-code emails. Single-row table. */
@Entity
@Table(name = "email_config")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "smtp_host", nullable = false)
    private String smtpHost;

    @Column(name = "smtp_port", nullable = false)
    private Integer smtpPort;

    @Column(name = "smtp_username", nullable = false)
    private String smtpUsername;

    @Column(name = "smtp_password", nullable = false)
    private String smtpPassword;

    @Column(name = "from_email", nullable = false)
    private String fromEmail;

    @Column(name = "from_name")
    private String fromName;

    @Column(name = "use_ssl", nullable = false)
    @Builder.Default
    private boolean useSsl = false;

    @Column(name = "use_tls", nullable = false)
    @Builder.Default
    private boolean useTls = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = false;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;
}
