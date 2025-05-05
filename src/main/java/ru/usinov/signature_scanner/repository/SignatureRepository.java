package ru.usinov.signature_scanner.repository;

import ru.usinov.signature_scanner.model.Signature;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface SignatureRepository extends JpaRepository<Signature, UUID> {
    List<Signature> findByUpdatedAtAfter(LocalDateTime since);
    List<Signature> findByIdIn(List<UUID> ids);
    List<Signature> findByStatus(String status);
    List<Signature> findByStatusNot(String status);
}

