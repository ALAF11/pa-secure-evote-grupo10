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

public class CertificateRevocationList {

    private static final Logger logger = LoggingUtil.getLogger(CertificateRevocationList.class);
    private final Map<String, RevocationInfo> revokedCertificates = new ConcurrentHashMap<>();

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

    public boolean isRevoked(String serialNumber) {
        return revokedCertificates.containsKey(serialNumber);
    }

    public boolean isRevoked(X509Certificate certificate) {
        return isRevoked(certificate.getSerialNumber().toString());
    }

    public RevocationInfo getRevocationInfo(String serialNumber) {
        return revokedCertificates.get(serialNumber);
    }

    public Set<String> getRevokedCertificatesSince(Instant since) {
        return revokedCertificates.entrySet().stream()
                .filter(entry -> entry.getValue().getTimestamp().isAfter(since))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    public Map<String, RevocationInfo> getAllRevokedCertificates() {
        return Collections.unmodifiableMap(revokedCertificates);
    }

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

    public static class RevocationInfo {
        private final Instant timestamp;
        private final String reason;

        public RevocationInfo(Instant timestamp, String reason) {
            this.timestamp = timestamp;
            this.reason = reason;
        }

        public Instant getTimestamp() {
            return timestamp;
        }

        public String getReason() {
            return reason;
        }
    }
}
