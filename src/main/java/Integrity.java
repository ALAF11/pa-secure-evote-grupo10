import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Integrity {

    public static byte[] generateDigest(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    public static boolean verifyDigest(byte[] digest, byte[] computeDigest) {
        return Arrays.equals(digest, computeDigest);
    }

    public static byte[] generateHMAC(byte[] message, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(message);
    }

    public static boolean verifyHMAC(byte[] message, byte[] key, byte[] receivedHmac) throws Exception {
        byte[] computedHmac = generateHMAC(message, key);
        return Arrays.equals(computedHmac, receivedHmac);
    }

}