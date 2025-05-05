package ru.usinov.signature_scanner;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Base64;

public class SignatureBuilder {
    public static void main(String[] args) throws Exception {
        File file = new File("C:\\Users\\dmitr\\OneDrive\\Рабочий стол\\Test Files\\Test.docx\\"); // Путь к файлу
        int firstByteCount = 5;              // Сколько байт в сигнатуре
        String threatName = "DocxSignature";
        String fileType = "docx";
        int offsetStart = 0;
        int offsetEnd = firstByteCount - 1;

        byte[] firstBytes;
        byte[] remainderBytes;

        try (FileInputStream fis = new FileInputStream(file)) {
            // 1. Чтение первых байт
            firstBytes = fis.readNBytes(firstByteCount);

            // 2. Остаток файла
            remainderBytes = fis.readAllBytes(); // Остаток после firstBytes
        }

        // Base64 кодирование firstBytes
        String firstBytesBase64 = Base64.getEncoder().encodeToString(firstBytes);

        // SHA-256 хеш остатка
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(remainderBytes);

        StringBuilder hashHex = new StringBuilder();
        for (byte b : hash) {
            hashHex.append(String.format("%02x", b));
        }

        // JSON-сигнатура
        System.out.println("{");
        System.out.println("  \"threatName\": \"" + threatName + "\",");
        System.out.println("  \"firstBytes\": \"" + firstBytesBase64 + "\",");
        System.out.println("  \"remainderHash\": \"" + hashHex + "\",");
        System.out.println("  \"remainderLength\": " + remainderBytes.length + ",");
        System.out.println("  \"fileType\": \"" + fileType + "\",");
        System.out.println("  \"offsetStart\": " + offsetStart + ",");
        System.out.println("  \"offsetEnd\": " + offsetEnd);
        System.out.println("}");
    }
}