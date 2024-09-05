import lombok.SneakyThrows;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Collectors;

public class AESCryptoUtil {
    /**
     * 키 반환
     */
    public static SecretKey getKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); // 지정 알고리즘에 대한 비밀키를 생성하는 KeyGeneratior 객체 반환
        keyGenerator.init(128); // 특정 키 크기에 대해 KeyGenrator를 초기화
        SecretKey secretKey = keyGenerator.generateKey(); // 비밀 키 생성
        return secretKey;
    }

    /**
     * 초기화 백터 반환 : 암호화 알고리즘은 AES를 사용하므로 초기화 벡터에 대한 코드 정의도 필요하다.
     */
    public static IvParameterSpec getIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv); // 지정한 바이트수의 난수 바이트를 생성한다.
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String specName, SecretKey key, IvParameterSpec iv, String plainText) throws  Exception {
        Cipher cipher = Cipher.getInstance(specName); //Cipher.getInstance 메서드로 지정된 변환을 구현하는 Cipher 클래스의 인스턴스를 생성해야 한다.
        cipher.init(Cipher.ENCRYPT_MODE, key, iv); //그리고 앞서 만든 키와 초기화 벡터로 Cipher 인스턴스를 초기화시키는 과정이 필요,암호화 모드
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)); // 문자열 암호화
        return new String(Base64.getEncoder().encode(encrypted)); //Base64 인코딩 스키마를 사용하여 지정된 바이트 배열의 모든 바이트를 새로 할당된 바이트 배열로 인코딩
    }

    public static String decrypt(String specName, SecretKey key, IvParameterSpec iv, String cipherText) throws  Exception {
        Cipher cipher = Cipher.getInstance(specName); //Cipher.getInstance 메서드로 지정된 변환을 구현하는 Cipher 클래스의 인스턴스를 생성해야 한다.
        cipher.init(Cipher.DECRYPT_MODE, key, iv); //그리고 앞서 만든 키와 초기화 벡터로 Cipher 인스턴스를 초기화시키는 과정이 필요,복호화 모드
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText)); // Base64 인코딩 스키마를 사용하여 지정된 바이트 배열의 모든 바이트를 새로 할당된 바이트 배열로 디코딩해 문자열 복호화
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    @SneakyThrows
    public static void main(String[] args) {
        String plainText = "Hello, MadPlay!";

        SecretKey key = AESCryptoUtil.getKey();
        IvParameterSpec ivParameterSpec = AESCryptoUtil.getIv();
        String specName = "AES/CBC/PKCS5Padding";

        String encryptedText = AESCryptoUtil.encrypt(specName, key, ivParameterSpec, plainText);
        String decryptedText = AESCryptoUtil.decrypt(specName, key, ivParameterSpec, encryptedText);

        System.out.println("cipherText: " + encryptedText);
        System.out.println("plainText: " + decryptedText);
    }

}
