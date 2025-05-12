package crypto;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Manages certificate revocation for e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Maintaining a list of revoked certificates and their
 *     revocation information</li>
 *     <li>Checking whether certificates have been revoked</li>
 *     <li>Providing revocation information for specific certificates</li>
 *     <li>Generating Certificate Revocation Lists (CRLs) for export</li>
 * </ul>
 * <p>
 * Thread-safe implementation using ConcurrentHashMap for managing
 * concurrent access to the revocation list.
 */

public class CertificateRevocationList {

    private static final Logger logger = LoggingUtil.getLogger(CertificateRevocationList.class);
    private final Map<String, RevocationInfo> revokedCertificates = new ConcurrentHashMap<>();

    /**
     * Revokes a certificate and adds it to the revocation list.
     *
     * @param serialNumber The serial number of the certificate to revoke
     * @param reason The reason for revocation
     * @return true if the certificate was successfully revoked, false if already revoked
     * @throws IllegalArgumentException If the serial number is null or empty
     */

    public boolean revokeCertificate(String serialNumber, String reason) {
        if (serialNumber == null || serialNumber.isEmpty()) {
            throw new IllegalArgumentException("Certificate serial number cannot be null or empty");
        }

        RevocationInfo revocationInfo = new RevocationInfo(Instant.now(), reason);
        RevocationInfo previous = revokedCertificates.put(serialNumber, revocationInfo);

        if (previous == null) {
            logger.info("Certificate {} revoked: {}", serialNumber, reason);
            return true;
        } else {
            logger.info("Certificate {} already revoked on {}: {}",
                    serialNumber, previous.getTimestamp(), previous.getReason());
            return false;
        }
    }

    /**
     * Checks if a certificate is revoked by its serial number.
     *
     * @param serialNumber The serial number of the certificate
     * @return true if the certificate is revoked, false otherwise
     */

    public boolean isRevoked(String serialNumber) {
        return revokedCertificates.containsKey(serialNumber);
    }

    /**
     * Checks if an X.509 certificate is revoked.
     *
     * @param certificate The X.509 certificate to check
     * @return true if the certificate is revoked, false otherwise
     */

    public boolean isRevoked(X509Certificate certificate) {
        return isRevoked(certificate.getSerialNumber().toString());
    }

    /**
     * Gets the revocation information for a specific certificate.
     *
     * @param serialNumber The serial number of the certificate
     * @return RevocationInfo object if the certificate is revoked,
     * null otherwise
     */

    public RevocationInfo getRevocationInfo(String serialNumber) {
        return revokedCertificates.get(serialNumber);
    }


    /**
     * Gets all revoked certificates and their revocation information.
     *
     * @return An unmodifiable map of all revoked certificates
     */

    public Map<String, RevocationInfo> getAllRevokedCertificates() {
        return Collections.unmodifiableMap(revokedCertificates);
    }

    /**
     * Exports the Certificate Revocation List in a formatted string.
     *
     * @return A formatted string containing the CRL information
     */

    public String exportCRL() {
        StringBuilder builder = new StringBuilder();
        builder.append("Certificate Revocation List\n");
        builder.append("Generated: ").append(Instant.now()).append("\n");
        builder.append("Revoked Certificates: ").append(revokedCertificates.size()).append("\n");

        for (Map.Entry<String, RevocationInfo> entry : revokedCertificates.entrySet()) {
            RevocationInfo info = entry.getValue();
            builder.append(entry.getKey())
                    .append(" | Revoked at: ").append(info.getTimestamp())
                    .append(" | Reason: ").append(info.getReason())
                    .append("\n");
        }

        return builder.toString();
    }

    /**
     * Inner class representing certificate revocation information
     */

    public static class RevocationInfo {
        private final Instant timestamp;
        private final String reason;

        /**
         * Constructs a new RevocationInfo with the specified timestamp
         * and reason.
         *
         * @param timestamp The time of revocation
         * @param reason The reason for revocation
         */

        public RevocationInfo(Instant timestamp, String reason) {
            this.timestamp = timestamp;
            this.reason = reason;
        }

        /**
         * Gets the timestamp when the certificate was revoked.
         *
         * @return The revocation timestamp
         */

        public Instant getTimestamp() {
            return timestamp;
        }

        /**
         * Gets the reason for certificate revocation.
         *
         * @return The revocation reason
         */

        public String getReason() {
            return reason;
        }
    }
}
