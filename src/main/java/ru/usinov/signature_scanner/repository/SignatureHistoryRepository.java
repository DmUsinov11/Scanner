package ru.usinov.signature_scanner.repository;

import ru.usinov.signature_scanner.model.SignatureHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureHistoryRepository extends JpaRepository<SignatureHistory, Long> {
}
