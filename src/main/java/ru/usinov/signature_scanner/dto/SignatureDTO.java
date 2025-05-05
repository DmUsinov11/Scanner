package ru.usinov.signature_scanner.dto;

import lombok.Data;

@Data
public class SignatureDTO {
    private String threatName;
    private String firstBytes;
    private String remainderHash;
    private int remainderLength;
    private String fileType;
    private int offsetStart;
    private int offsetEnd;
}

