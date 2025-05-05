package ru.usinov.signature_scanner.controller;

import ru.usinov.signature_scanner.dto.SignatureScanResult;
import ru.usinov.signature_scanner.service.FileScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
public class FileScanController {

    private final FileScanService fileScanService;

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public List<SignatureScanResult> uploadAndScan(@RequestParam("file") MultipartFile file) throws IOException {
        return fileScanService.scanFile(file);
    }
}

