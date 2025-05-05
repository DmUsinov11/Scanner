package ru.usinov.signature_scanner.service;

import ru.usinov.signature_scanner.dto.SignatureScanResult;
import ru.usinov.signature_scanner.model.Signature;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.MessageDigest;
import java.util.*;

@Service
@RequiredArgsConstructor
public class FileScanService {

    private final SignatureService signatureService;

    private static final int WINDOW_SIZE = 8;
    private static final int CHUNK_SIZE = 8192;
    private static final long BASE = 256;
    private static final long MOD = 1_000_000_007;

    public List<SignatureScanResult> scanFile(MultipartFile file) throws IOException {
        List<Signature> signatures = signatureService.getAllActualSignatures();
        List<SignatureScanResult> results = new ArrayList<>();

        // Группируем сигнатуры по длине firstBytes
        Map<Integer, Map<Long, List<Signature>>> hashIndexByLength = new HashMap<>();
        for (Signature sig : signatures) {
            int len = sig.getFirstBytes().length;
            long hash = computeHash(sig.getFirstBytes());

            hashIndexByLength
                    .computeIfAbsent(len, k -> new HashMap<>())
                    .computeIfAbsent(hash, k -> new ArrayList<>())
                    .add(sig);
        }

        File tempFile = File.createTempFile("scan-", ".bin");
        file.transferTo(tempFile);

        try (RandomAccessFile raf = new RandomAccessFile(tempFile, "r")) {
            long fileSize = raf.length();

            for (Map.Entry<Integer, Map<Long, List<Signature>>> entry : hashIndexByLength.entrySet()) {
                int windowSize = entry.getKey();
                Map<Long, List<Signature>> rollingHashIndex = entry.getValue();

                if (fileSize < windowSize) continue;

                byte[] window = new byte[windowSize];
                long rollingHash = 0;
                long pow = 1;

                raf.seek(0);
                byte[] buffer = new byte[(int) fileSize];
                raf.readFully(buffer);

                // Precompute power
                for (int i = 1; i < windowSize; i++) {
                    pow = (pow * 256) % 1_000_000_007;
                }

                for (int i = 0; i <= buffer.length - windowSize; i++) {
                    if (i == 0) {
                        rollingHash = computeHash(buffer, 0, windowSize);
                    } else {
                        rollingHash = (
                                (rollingHash + 1_000_000_007 - (buffer[i - 1] & 0xFF) * pow % 1_000_000_007) * 256 +
                                        (buffer[i + windowSize - 1] & 0xFF)
                        ) % 1_000_000_007;
                    }

                    if (rollingHashIndex.containsKey(rollingHash)) {
                        byte[] candidate = Arrays.copyOfRange(buffer, i, i + windowSize);

                        for (Signature sig : rollingHashIndex.get(rollingHash)) {
                            if (i >= sig.getOffsetStart() && i <= sig.getOffsetEnd()) {
                                if (Arrays.equals(sig.getFirstBytes(), candidate)) {
                                    int tailStart = i + windowSize;
                                    int tailEnd = tailStart + sig.getRemainderLength();

                                    if (tailEnd <= buffer.length) {
                                        byte[] tail = Arrays.copyOfRange(buffer, tailStart, tailEnd);
                                        String tailHash = hashSHA256(tail);

                                        if (tailHash.equals(sig.getRemainderHash())) {
                                            results.add(SignatureScanResult.builder()
                                                    .signatureId(sig.getId())
                                                    .threatName(sig.getThreatName())
                                                    .offsetFromStart(i)
                                                    .offsetFromEnd(tailEnd - 1)
                                                    .matched(true)
                                                    .build());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        tempFile.delete();
        return results;
    }

    private long computeHash(byte[] data) {
        long hash = 0;
        for (byte b : data) {
            hash = (hash * BASE + (b & 0xFF)) % MOD;
        }
        return hash;
    }

    private String hashSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing tail", e);
        }
    }

    private long computeHash(byte[] data, int start, int len) {
        long hash = 0;
        for (int i = start; i < start + len; i++) {
            hash = (hash * BASE + (data[i] & 0xFF)) % MOD;
        }
        return hash;
    }

}