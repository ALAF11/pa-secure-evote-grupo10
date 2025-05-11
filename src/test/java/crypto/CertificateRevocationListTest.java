package crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class CertificateRevocationListTest {

    private CertificateRevocationList crl;
    private final String SERIAL_NUMBER_1 = "12345";
    private final String SERIAL_NUMBER_2 = "67890";
    private final String REASON_1 = "Key compromise";
    private final String REASON_2 = "Affiliation changed";

    @BeforeEach
    void setUp() {
        crl = new CertificateRevocationList();
    }

    @Test
    @DisplayName("Test revoking a certificate")
    void testRevokeCertificate() {
        // Test revoking a certificate for the first time
        boolean result = crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);
        assertTrue(result);
        assertTrue(crl.isRevoked(SERIAL_NUMBER_1));

        // Test revoking an already revoked certificate
        boolean secondResult = crl.revokeCertificate(SERIAL_NUMBER_1, REASON_2);
        assertFalse(secondResult);
    }

    @Test
    @DisplayName("Test revoking a certificate with null or empty serial number")
    void testRevokeCertificateWithInvalidSerialNumber() {
        // Test with null serial number
        assertThrows(IllegalArgumentException.class, () -> crl.revokeCertificate(null, REASON_1));

        // Test with empty serial number
        assertThrows(IllegalArgumentException.class, () -> crl.revokeCertificate("", REASON_1));
    }

    @Test
    @DisplayName("Test checking if a certificate is revoked by serial number")
    void testIsRevokedBySerialNumber() {

        crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);

        // Test with revoked certificate
        assertTrue(crl.isRevoked(SERIAL_NUMBER_1));

        // Test with non-revoked certificate
        assertFalse(crl.isRevoked(SERIAL_NUMBER_2));
    }

    @Test
    @DisplayName("Test checking if a certificate is revoked by X509Certificate")
    void testIsRevokedByX509Certificate() {

        crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);

        // Create mock X509Certificate
        X509Certificate mockCert1 = Mockito.mock(X509Certificate.class);
        X509Certificate mockCert2 = Mockito.mock(X509Certificate.class);

        when(mockCert1.getSerialNumber()).thenReturn(new BigInteger(SERIAL_NUMBER_1));
        when(mockCert2.getSerialNumber()).thenReturn(new BigInteger(SERIAL_NUMBER_2));

        // Test with revoked certificate
        assertTrue(crl.isRevoked(mockCert1));

        // Test with non-revoked certificate
        assertFalse(crl.isRevoked(mockCert2));
    }

    @Test
    @DisplayName("Test getting revocation info")
    void testGetRevocationInfo() {

        crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);

        // Test get info for revoked certificate
        CertificateRevocationList.RevocationInfo info = crl.getRevocationInfo(SERIAL_NUMBER_1);
        assertNotNull(info);
        assertEquals(REASON_1, info.getReason());

        // Test get info for non-revoked certificate
        assertNull(crl.getRevocationInfo(SERIAL_NUMBER_2));
    }


    @Test
    @DisplayName("Test getting all revoked certificates")
    void testGetAllRevokedCertificates() {

        crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);
        crl.revokeCertificate(SERIAL_NUMBER_2, REASON_2);

        Map<String, CertificateRevocationList.RevocationInfo> allRevoked = crl.getAllRevokedCertificates();
        assertEquals(2, allRevoked.size());
        assertTrue(allRevoked.containsKey(SERIAL_NUMBER_1));
        assertTrue(allRevoked.containsKey(SERIAL_NUMBER_2));
        assertEquals(REASON_1, allRevoked.get(SERIAL_NUMBER_1).getReason());
        assertEquals(REASON_2, allRevoked.get(SERIAL_NUMBER_2).getReason());

        // Test that the returned map is unmodifiable
        assertThrows(UnsupportedOperationException.class, () ->
                allRevoked.put("12345", new CertificateRevocationList.RevocationInfo(Instant.now(), "Test")));
    }

    @Test
    @DisplayName("Test exporting CRL as string")
    void testExportCRL() {

        crl.revokeCertificate(SERIAL_NUMBER_1, REASON_1);
        crl.revokeCertificate(SERIAL_NUMBER_2, REASON_2);

        String exported = crl.exportCRL();
        assertNotNull(exported);
        assertTrue(exported.contains("Certificate Revocation List"));
        assertTrue(exported.contains("Revoked Certificates: 2"));
        assertTrue(exported.contains(SERIAL_NUMBER_1));
        assertTrue(exported.contains(REASON_1));
        assertTrue(exported.contains(SERIAL_NUMBER_2));
        assertTrue(exported.contains(REASON_2));
    }
}
