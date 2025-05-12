package crypto;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptoUtils {

    private CryptoUtils(){
        // Prevent instantiation
    }

    public static byte[] encryptVote(String vote, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        GCMParameterSpec gcmParametersSpec = new GCMParameterSpec(128, iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParametersSpec);
        byte[] encryptedVote = aesCipher.doFinal(vote.getBytes());

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        ByteBuffer buffer = ByteBuffer.allocate(4 + encryptedKey.length + 4 + iv.length + 4 + encryptedVote.length);
        buffer.putInt(encryptedKey.length);
        buffer.put(encryptedKey);
        buffer.putInt(iv.length);
        buffer.put(iv);
        buffer.putInt(encryptedVote.length);
        buffer.put(encryptedVote);

        return buffer.array();
    }

    public static String encodeCertificateToPEM(X509Certificate cert) throws CertificateEncodingException {
        Base64.Encoder encoder = Base64.getEncoder();
        String encoded = encoder.encodeToString(cert.getEncoded());

        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");

        int lineLength = 64;
        for( int i = 0; i < encoded.length(); i += lineLength) {
            int endIndex = Math.min(i + lineLength, encoded.length());
            pem.append(encoded, i, endIndex).append("\n");
        }

        pem.append("-----END CERTIFICATE-----");
        return pem.toString();

    }

    public static X509Certificate decodeCertificateFromPEM(String pemCertificate) throws GeneralSecurityException {
        String base64Cert = pemCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(base64Cert);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }

}

