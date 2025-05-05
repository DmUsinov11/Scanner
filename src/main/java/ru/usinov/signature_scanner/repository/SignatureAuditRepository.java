package ru.usinov.signature_scanner.repository;

import ru.usinov.signature_scanner.model.SignatureAudit;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureAuditRepository extends JpaRepository<SignatureAudit, Long> {
}
