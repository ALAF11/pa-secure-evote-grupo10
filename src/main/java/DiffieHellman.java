import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class DiffieHellman {
    private static final BigInteger N = new BigInteger( "1289971646" , 16);
    private static final BigInteger G = new BigInteger( "2" , 16);

    public static BigInteger generatePrivateKey() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        return new BigInteger(2048, random);
    }

    public static BigInteger computeShareSecret(BigInteger privateKey) {
        return G.modPow(privateKey, N);
    }
    public static BigInteger computeShareSecret(BigInteger publicKey, BigInteger privateKey) {
        return publicKey.modPow(privateKey, N);
    }
}
