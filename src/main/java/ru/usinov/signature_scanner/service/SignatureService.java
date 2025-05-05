package ru.usinov.signature_scanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.usinov.signature_scanner.dto.SignatureDTO;
import ru.usinov.signature_scanner.model.Signature;
import ru.usinov.signature_scanner.model.SignatureAudit;
import ru.usinov.signature_scanner.model.SignatureHistory;
import ru.usinov.signature_scanner.repository.SignatureAuditRepository;
import ru.usinov.signature_scanner.repository.SignatureHistoryRepository;
import ru.usinov.signature_scanner.repository.SignatureRepository;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class SignatureService {

    private final SignatureRepository signatureRepository;
    private final SignatureHistoryRepository historyRepository;
    private final SignatureAuditRepository auditRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Signature> getAllActualSignatures() {
        return signatureRepository.findByStatusNot("DELETED");
    }

    public List<Signature> getDiffSince(LocalDateTime since) {
        return signatureRepository.findByUpdatedAtAfter(since);
    }

    public Optional<Signature> getById(UUID id) {
        return signatureRepository.findById(id);
    }

    public List<Signature> getByIdList(List<UUID> ids) {
        return signatureRepository.findByIdIn(ids);
    }

    public Signature save(Signature signature) {
        signature.setUpdatedAt(LocalDateTime.now());
        signature.setStatus("ACTUAL");
        return signatureRepository.save(signature);
    }

    public void delete(UUID id) {
        signatureRepository.findById(id).ifPresent(sig -> {
            historyRepository.save(SignatureHistory.builder()
                    .signatureId(sig.getId())
                    .versionCreatedAt(LocalDateTime.now())
                    .threatName(sig.getThreatName())
                    .firstBytes(sig.getFirstBytes())
                    .remainderHash(sig.getRemainderHash())
                    .remainderLength(sig.getRemainderLength())
                    .fileType(sig.getFileType())
                    .offsetStart(sig.getOffsetStart())
                    .offsetEnd(sig.getOffsetEnd())
                    .status(sig.getStatus())
                    .updatedAt(sig.getUpdatedAt())
                    .build()
            );

            sig.setStatus("DELETED");
            sig.setUpdatedAt(LocalDateTime.now());
            signatureRepository.save(sig);

            auditRepository.save(SignatureAudit.builder()
                    .signatureId(sig.getId())
                    .changedBy("system")
                    .changeType("DELETED")
                    .changedAt(LocalDateTime.now())
                    .fieldsChanged("{\"status\": \"DELETED\"}")
                    .build()
            );
        });
    }

    public Signature updateSignature(UUID id, SignatureDTO dto, String changedBy) {
        Signature signature = signatureRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Signature not found"));

        SignatureHistory history = SignatureHistory.builder()
                .signatureId(signature.getId())
                .versionCreatedAt(LocalDateTime.now())
                .threatName(signature.getThreatName())
                .firstBytes(signature.getFirstBytes())
                .remainderHash(signature.getRemainderHash())
                .remainderLength(signature.getRemainderLength())
                .fileType(signature.getFileType())
                .offsetStart(signature.getOffsetStart())
                .offsetEnd(signature.getOffsetEnd())
                .status(signature.getStatus())
                .updatedAt(signature.getUpdatedAt())
                .build();
        historyRepository.save(history);

        Map<String, Object> changes = new LinkedHashMap<>();
        if (!Objects.equals(signature.getThreatName(), dto.getThreatName())) {
            changes.put("threatName", dto.getThreatName());
            signature.setThreatName(dto.getThreatName());
        }
        if (!Arrays.equals(signature.getFirstBytes(), Base64.getDecoder().decode(dto.getFirstBytes()))) {
            changes.put("firstBytes", dto.getFirstBytes());
            signature.setFirstBytes(Base64.getDecoder().decode(dto.getFirstBytes()));
        }
        if (!Objects.equals(signature.getRemainderHash(), dto.getRemainderHash())) {
            changes.put("remainderHash", dto.getRemainderHash());
            signature.setRemainderHash(dto.getRemainderHash());
        }
        if (!Objects.equals(signature.getRemainderLength(), dto.getRemainderLength())) {
            changes.put("remainderLength", dto.getRemainderLength());
            signature.setRemainderLength(dto.getRemainderLength());
        }
        if (!Objects.equals(signature.getFileType(), dto.getFileType())) {
            changes.put("fileType", dto.getFileType());
            signature.setFileType(dto.getFileType());
        }
        if (!Objects.equals(signature.getOffsetStart(), dto.getOffsetStart())) {
            changes.put("offsetStart", dto.getOffsetStart());
            signature.setOffsetStart(dto.getOffsetStart());
        }
        if (!Objects.equals(signature.getOffsetEnd(), dto.getOffsetEnd())) {
            changes.put("offsetEnd", dto.getOffsetEnd());
            signature.setOffsetEnd(dto.getOffsetEnd());
        }

        signature.setUpdatedAt(LocalDateTime.now());
        Signature updated = signatureRepository.save(signature);

        try {
            String json = objectMapper.writeValueAsString(changes);
            SignatureAudit audit = SignatureAudit.builder()
                    .signatureId(signature.getId())
                    .changedBy(changedBy)
                    .changeType("UPDATED")
                    .changedAt(LocalDateTime.now())
                    .fieldsChanged(json)
                    .build();
            auditRepository.save(audit);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write audit log", e);
        }

        return updated;
    }

}
