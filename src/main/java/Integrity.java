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

}