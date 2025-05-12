package crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import crypto.CryptoUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Date;

public class CryptoUtilsTest {

    private KeyPair rsaKeyPair;
    private X509Certificate testCertificate;

    @BeforeEach
    public void setUp() throws Exception {
        // Generate RSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();

        // Create a self-signed certificate for testing
        testCertificate = generateSelfSignedCertificate();
    }

    @Test
    @DisplayName("Tests hybrid encryption and decryption of vote data")
    public void testEncryptAndDecryptVote() throws Exception {
        // Test data
        String voteData = "Candidate1";

        // Encrypt the vote
        byte[] encryptedData = CryptoUtils.encryptVote(voteData, rsaKeyPair.getPublic());

        // Verify the structure of encrypted data
        assertNotNull(encryptedData);
        assertTrue(encryptedData.length > 0);

        // For a complete test, we would need a decryptVote method
        // This would verify the roundtrip works correctly
    }

    @Test
    @DisplayName("Tests encoding an X.509 certificate to PEM format and back")
    public void testCertificateEncodingAndDecoding() throws Exception {
        // Encode certificate to PEM
        String pemCertificate = CryptoUtils.encodeCertificateToPEM(testCertificate);

        // Verify PEM format
        assertTrue(pemCertificate.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(pemCertificate.endsWith("-----END CERTIFICATE-----"));

        // Decode back to X509Certificate
        X509Certificate decodedCertificate = CryptoUtils.decodeCertificateFromPEM(pemCertificate);

        // Verify they are the same certificate
        assertNotNull(decodedCertificate);
        assertArrayEquals(testCertificate.getEncoded(), decodedCertificate.getEncoded());
    }

    @Test
    @DisplayName("Tests hashing functionality")
    public void testHash() throws Exception {
        // Test data
        byte[] data = "Test data for hashing".getBytes();

        // Generate hash
        byte[] hashedData = CryptoUtils.hash(data);

        // Verify hash properties
        assertNotNull(hashedData);
        assertEquals(32, hashedData.length); // SHA-256 produces 32-byte hashes

        // Different inputs should produce different hashes
        byte[] differentData = "Different test data".getBytes();
        byte[] differentHash = CryptoUtils.hash(differentData);
        assertFalse(java.util.Arrays.equals(hashedData, differentHash));
    }

    @Test
    @DisplayName("Tests digital signature creation and verification")
    public void testSignAndVerify() throws Exception {
        // Test data
        byte[] data = "Test data for signing".getBytes();

        // Generate signature
        byte[] signature = CryptoUtils.sign(data, rsaKeyPair.getPrivate());

        // Verify signature
        boolean isValid = CryptoUtils.verifySignature(data, signature, rsaKeyPair.getPublic());
        assertTrue(isValid);

        // Modify data and verify signature fails
        byte[] tamperedData = "Tampered test data".getBytes();
        boolean shouldFail = CryptoUtils.verifySignature(tamperedData, signature, rsaKeyPair.getPublic());
        assertFalse(shouldFail);
    }

    /**
     * Helper method to generate a self-signed certificate for testing
     */
    private X509Certificate generateSelfSignedCertificate()
            throws OperatorCreationException, CertificateException {
        X500Principal subject = new X500Principal("CN=Test");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, rsaKeyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaKeyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }
}