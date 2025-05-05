package ru.usinov.signature_scanner.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "signature_audit")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignatureAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long auditId;

    private UUID signatureId;

    private String changedBy;

    private String changeType;

    private LocalDateTime changedAt;

    @Lob
    private String fieldsChanged;
}
