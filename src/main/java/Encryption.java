import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class Encryption {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static byte[] encryptRSA(byte[] message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message);
    }

    public static byte[] decryptRSA(byte[] message, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(message);
    }

    public static byte[] encryptAES(byte[] message, byte[] key) {

        try {
            byte[] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
            SecretKeySpec keySpec = new SecretKeySpec(secretKeyPadded, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(message);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(iv);
            outputStream.write(encrypted);
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptAES(byte[] message, byte[] key) {

        try {
            byte[] iv = Arrays.copyOfRange(message, 0, 16);
            byte[] encrypted = Arrays.copyOfRange(message, 16, message.length);

            byte[] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
            SecretKeySpec keySpec = new SecretKeySpec(secretKeyPadded, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}