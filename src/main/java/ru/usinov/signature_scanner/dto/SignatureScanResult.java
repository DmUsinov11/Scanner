package ru.usinov.signature_scanner.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SignatureScanResult {
    private UUID signatureId;
    private String threatName;
    private int offsetFromStart;
    private int offsetFromEnd;
    private boolean matched;
}

