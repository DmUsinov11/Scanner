package ru.usinov.signature_scanner.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "signature_history")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignatureHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long historyId;

    private UUID signatureId;

    private LocalDateTime versionCreatedAt;

    private String threatName;

    @Lob
    private byte[] firstBytes;

    private String remainderHash;

    private int remainderLength;

    private String fileType;

    private int offsetStart;

    private int offsetEnd;

    private String status;

    private LocalDateTime updatedAt;
}
