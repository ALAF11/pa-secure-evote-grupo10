package crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyManager {

    private static final String RSA = "RSA";

    public static PrivateKey loadPrivateKey (String filePath) throws Exception {
        String keyPEM = readKey(filePath);
        keyPEM = keyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(keySpec);
    }

    public static PublicKey loadPublicKey (String filePath) throws Exception {
        String keyPEM = readKey(filePath);
        keyPEM = keyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(keyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(keySpec);
    }

    public static void generateAndStoreKeyPair(String privatePath,String publicPath) throws Exception{
        KeyPair pair = CryptoUtils.generateKeyPair();
        writeKey(pair.getPrivate().getEncoded(), "PRIVATE KEY", privatePath);
        writeKey(pair.getPublic().getEncoded(), "PUBLIC KEY", publicPath);

    }

    public static boolean keyPairExists(String privatePath,String publicPath){
        return Files.exists(Paths.get(privatePath)) && Files.exists(Paths.get(publicPath));
    }


    private static String readKey (String path) throws IOException{
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    private static void writeKey(byte[] keyBytes, String type, String filePath) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(keyBytes);
        String pem = "-----BEGIN " + type + "-----\n"
                + chunk(base64, 64)
                + "-----END " + type + "-----\n";

        Files.createDirectories(Paths.get(filePath).getParent());
        Files.write(Paths.get(filePath), pem.getBytes());
    }

    private static String chunk(String data, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length(); i += length) {
            sb.append(data, i, Math.min(i + length, data.length())).append("\n");
        }
        return sb.toString();
    }

}
