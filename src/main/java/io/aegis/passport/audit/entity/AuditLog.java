package io.aegis.passport.audit.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A recorded administrative or security-relevant action, written
 * asynchronously by the audit aspect.
 */
@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_audit_module", columnList = "module"),
        @Index(name = "idx_audit_operator", columnList = "operator_name"),
        @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_success", columnList = "success")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", unique = true, nullable = false, length = 64)
    private String eventId;

    @Column(nullable = false, length = 50)
    private String module;

    @Column(nullable = false, length = 50)
    private String action;

    @Column(length = 255)
    private String description;

    @Column(name = "operator_name", length = 100)
    private String operatorName;

    @Column(name = "target_id", length = 100)
    private String targetId;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "request_method", length = 10)
    private String requestMethod;

    @Column(name = "request_path", length = 255)
    private String requestPath;

    @Column(columnDefinition = "TEXT")
    private String params;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "execution_ms")
    private Long executionMs;

    @Column(nullable = false)
    private Instant timestamp;
}
