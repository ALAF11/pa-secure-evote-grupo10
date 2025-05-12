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

/**
 * Utility class providing cryptographic operations for the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Encrypting votes using hybrid encryption (AES + RSA)</li>
 *     <li>Encoding and decoding X.509 certificates in PEM format</li>
 *     <li>Creating and verifying digital signatures</li>
 *     <li>Computing cryptographic hashes of messages</li>
 * </ul>
 * <p>
 * The class uses industry-standard cryptographic algorithms and practices.
 */

public class CryptoUtils {

    /**
     * Private constructor to prevent instantiation of utility class.
     */

    private CryptoUtils(){
        // Prevent instantiation
    }

    /**
     * Encrypts a vote using hybrid encryption (AES + RSA).
     * <p>
     * The method:
     * <ul>
     *     <li>Generates a random AES key</li>
     *     <li>Encrypts the vote with AES-GCM</li>
     *     <li>Encrypts the AES key with RSA-OAEP</li>
     *     <li>Combines the encrypted key, IV, and encrypted vote into
     *     a single byte array</li>
     * </ul>
     *
     * @param vote The vote to encrypt (as a string)
     * @param publicKey The public key of the tallying authority
     * @return A byte array containing the encrypted vote
     * @throws NoSuchAlgorithmException If crypto algorithm unavailable
     * @throws NoSuchPaddingException If padding scheme unavailable
     * @throws InvalidKeyException If key is invalid
     * @throws IllegalBlockSizeException If encryption fails
     * @throws BadPaddingException If padding fails
     * @throws InvalidAlgorithmParameterException If IV parameters are invalid
     */

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

    /**
     * Encodes an X.509 certificate to PEM format.
     *
     * @param cert The X.509 certificate to encode
     * @return A string containing the certificate in PEM format
     * @throws CertificateEncodingException If encoding fails
     */

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

    /**
     * Decodes an X.509 certificate from PEM format.
     *
     * @param pemCertificate The certificate in PEM format
     * @return An X509Certificate object
     * @throws GeneralSecurityException If decoding fails
     */

    public static X509Certificate decodeCertificateFromPEM(String pemCertificate) throws GeneralSecurityException {
        String base64Cert = pemCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(base64Cert);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     * Computes a SHA-256 hash of a message.
     *
     * @param message The message to hash
     * @return The hash value as a byte array
     * @throws NoSuchAlgorithmException If SHA-256 is not available
     */

    public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    /**
     * Signs a message using SHA256withRSA.
     *
     * @param message The message to sign
     * @param privateKey The private key to use for signing
     * @return The signature as a byte array
     * @throws Exception If signing fails
     */

    public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    /**
     * Verifies a SHA256withRSA signature.
     *
     * @param message The original message
     * @param signatureBytes The signature to verify
     * @param publicKey The public key for verification
     * @return true if the signature is valid, false otherwise
     * @throws Exception If verification fails
     */

    public static boolean verifySignature(byte[] message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }

}

