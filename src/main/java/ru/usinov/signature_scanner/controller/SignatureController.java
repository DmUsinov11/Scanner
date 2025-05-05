package ru.usinov.signature_scanner.controller;

import ru.usinov.signature_scanner.dto.SignatureDTO;
import ru.usinov.signature_scanner.model.Signature;
import ru.usinov.signature_scanner.model.SignatureAudit;
import ru.usinov.signature_scanner.model.SignatureHistory;
import ru.usinov.signature_scanner.repository.SignatureAuditRepository;
import ru.usinov.signature_scanner.repository.SignatureHistoryRepository;
import ru.usinov.signature_scanner.service.SignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/signatures")
@RequiredArgsConstructor
public class SignatureController {

    private final SignatureService signatureService;
    private final SignatureAuditRepository auditRepository;
    private final SignatureHistoryRepository historyRepository;

    @GetMapping("/{id}/audit")
    public List<SignatureAudit> getAudit(@PathVariable UUID id) {
        return auditRepository.findAll().stream()
                .filter(a -> a.getSignatureId().equals(id))
                .toList();
    }

    @GetMapping("/{id}/history")
    public List<SignatureHistory> getHistory(@PathVariable UUID id) {
        return historyRepository.findAll().stream()
                .filter(h -> h.getSignatureId().equals(id))
                .toList();
    }

    @GetMapping
    public List<Signature> getAllActual() {
        return signatureService.getAllActualSignatures();
    }

    @GetMapping("/diff")
    public List<Signature> getDiff(
            @RequestParam("since")
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
            LocalDateTime since) {
        return signatureService.getDiffSince(since);
    }

    @GetMapping("/{id}")
    public Signature getById(@PathVariable UUID id) {
        return signatureService.getById(id)
                .orElseThrow(() -> new RuntimeException("Signature not found"));
    }

    @PostMapping("/by-ids")
    public List<Signature> getByIds(@RequestBody List<UUID> ids) {
        return signatureService.getByIdList(ids);
    }

    @PostMapping
    public Signature create(@RequestBody SignatureDTO dto) {
        byte[] decodedFirstBytes = Base64.getDecoder().decode(dto.getFirstBytes());

        Signature sig = Signature.builder()
                .threatName(dto.getThreatName())
                .firstBytes(decodedFirstBytes)
                .remainderHash(dto.getRemainderHash())
                .remainderLength(dto.getRemainderLength())
                .fileType(dto.getFileType())
                .offsetStart(dto.getOffsetStart())
                .offsetEnd(dto.getOffsetEnd())
                .status("ACTUAL")
                .updatedAt(LocalDateTime.now())
                .build();

        return signatureService.save(sig);
    }


    @DeleteMapping("/{id}")
    public void delete(@PathVariable UUID id) {
        signatureService.delete(id);
    }

    @PutMapping("/{id}")
    public Signature updateSignature(
            @PathVariable UUID id,
            @RequestBody SignatureDTO dto
    ) {
        return signatureService.updateSignature(id, dto, "system");
    }

}

