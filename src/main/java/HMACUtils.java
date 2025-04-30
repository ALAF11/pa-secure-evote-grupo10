import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class HMACUtils {

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance("HmacSHA256").generateKey();
    }

    public static byte[] compute(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

}