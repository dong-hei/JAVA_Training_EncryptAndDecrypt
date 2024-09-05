import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Collectors;

public class AESFileCryptoUtil {
    public static void encryptFile(String specName, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile) throws Exception {

        Cipher cipher = Cipher.getInstance(specName);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        try (FileOutputStream output = new FileOutputStream(outputFile);
             CipherOutputStream cipherOutput = new CipherOutputStream(output, cipher)) { // CipherOutputStream은 OutputStream과 Cipher로 구성되어 write() 메서드가 데이터를 쓰기 전에 먼저 데이터 암호화를 시도한다.

            String data = Files.lines(inputFile.toPath()).collect(Collectors.joining("\n"));
            cipherOutput.write(data.getBytes(StandardCharsets.UTF_8));
        }
    }

    public static void decryptFile(String specName, SecretKey key, IvParameterSpec iv, File encryptedFile, File decryptedFile) throws Exception {

        Cipher cipher = Cipher.getInstance(specName);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        try (
                CipherInputStream cipherInput = new CipherInputStream(new FileInputStream(encryptedFile), cipher); // 데이터 복호화를 시도하고 암호화된 파일을 읽어온다.
                InputStreamReader inputStream = new InputStreamReader(cipherInput); // 바이트 스트림에서 문자 스트림으로의 다리이다.
                BufferedReader reader = new BufferedReader(inputStream);  // 최고의 효율성을 위해
                FileOutputStream fileOutput = new FileOutputStream(decryptedFile)) {

            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            fileOutput.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    @SneakyThrows
    public static void main(String[] args) {

        SecretKey key = AESCryptoUtil.getKey();
        String specName = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = AESCryptoUtil.getIv();

        File inputFile = Paths.get("input.txt").toFile();
        File encryptedFile = new File("encrypted.txt");
        File decryptedFile = new File("decrypted.txt");
        AESFileCryptoUtil.encryptFile(specName, key, ivParameterSpec, inputFile, encryptedFile);
        AESFileCryptoUtil.decryptFile(specName, key, ivParameterSpec, encryptedFile, decryptedFile);

// 결과 확인용
        String inputText = Files.lines(Paths.get("input.txt"), StandardCharsets.UTF_8)
                .collect(Collectors.joining("\n"));
        String encryptedText = Files.lines(Paths.get("decrypted.txt"), StandardCharsets.UTF_8)
                .collect(Collectors.joining("\n"));

        System.out.println("input: " + inputText);
        System.out.println("decrypted: " + encryptedText);
    }
}
