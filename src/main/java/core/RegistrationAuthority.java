package core;

import crypto.CertificateRevocationList;
import model.ElectionManager;
import model.ElectionPhase;
import model.Voter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.KeyUnwrapper;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents the Registration Authority in the e-voting system.
 * <p>
 * <ul>
 *     <li>Maintaining the list of eligible voters</li>
 *     <li>Issuing X.509 certificates to authenticated voters</li>
 *     <li>Sharing eligible voter information with the Voting Server</li>
 *     <li>Managing certificate revocation through a Certificate Revocation List (CRL)</li>
 * </ul>
 * <p>
 * The Registration Authority operates primarily during the registration phase of an election,
 * as managed by the ElectionManager.
 */

public class RegistrationAuthority {

    private static final Logger logger = LoggingUtil.getLogger(RegistrationAuthority.class);
    private final KeyPair keyPair;
    private final Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
    private final CertificateRevocationList crl = new CertificateRevocationList();
    private final ElectionManager electionManager;
    private final Map<String, String> serialNumberToVoterId = new ConcurrentHashMap<>();

    /**
     * Constructs a new Registration Authority with the specified election manager.
     *
     * @param electionManager The election manager for phase control
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available
     */

    public RegistrationAuthority(ElectionManager electionManager) throws NoSuchAlgorithmException {
        this.electionManager = electionManager;
        logger.info("Initializing Registration Authority");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        this.keyPair = keyGen.generateKeyPair();

        logger.info("Registration Authority initialized successfully");
    }

    /**
     * Registers a voter as eligible to participate in the election.
     * <p>
     * This method can only be called during the registration phase.
     *
     * @param voterId The unique identifier of the voter
     * @return true if the voter was successfully registered, false if already registered
     * @throws IllegalStateException If not in the registration phase
     */

    public boolean registerEligibleVoter(String voterId) {
        if (!electionManager.isInPhase(ElectionPhase.REGISTRATION)) {
            logger.warn("Cannot register voter outside of registration phase");
            throw new IllegalStateException("Voter registration is not currently active");
        }

        if (eligibleVoters.putIfAbsent(voterId, true) == null) {
            logger.info("Voter {} registered as eligible", voterId);
            return true;
        } else {
            logger.info("Voter {} already registered as eligible", voterId);
            return false;
        }
    }

    /**
     * Removes a voter from the list of eligible voters.
     *
     * @param voterId The unique identifier of the voter
     * @return true if the voter was removed, false if not found
     */

    public boolean removeEligibleVoter(String voterId) {
        if (eligibleVoters.remove(voterId) != null) {
            logger.info("Voter {} removed from eligible voters list", voterId);
            return true;
        } else {
            logger.info("Voter {} not found in eligible voters list", voterId);
            return false;
        }
    }

    /**
     * Issues an X.509 certificate to an eligible voter.
     * <p>
     * This method can only be called during the registration phase.
     *
     * @param voter The voter object containing identification and public key
     * @return A signed X.509 certificate
     * @throws OperatorCreationException If there's an error creating the certificate
     * @throws CertificateException If there's an error with the certificate
     * @throws IllegalStateException If not in the registration phase
     * @throws SecurityException If the voter is not eligible
     */

    public X509Certificate issueCertificate(Voter voter) throws OperatorCreationException, CertificateException {
        String transactionId = "CERT_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(transactionId);

        try {
            if (!electionManager.isInPhase(ElectionPhase.REGISTRATION)) {
                logger.warn("Cannot issue certificate outside of registration phase");
                throw new IllegalStateException("Certificate issuance is not currently active");
            }

            String voterId = voter.getId();

            // Check if voter is eligible
            if (!eligibleVoters.containsKey(voterId)) {
                logger.warn("Certificate issuance failed: voter {} is not eligible", voterId);
                throw new SecurityException("Voter is not eligible for certificate issuance");
            }

            // Generate certificate details
            BigInteger serialNumber = new BigInteger(128, new SecureRandom());
            Date notBefore = new Date();
            Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

            X500Name issuerName = new X500Name("CN=Registration Authority");
            X500Name subjectName = new X500Name("CN=" + voterId);

            PublicKey voterPublicKey = voter.getPublicKey();
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                    voterPublicKey.getEncoded());

            // Create certificate builder
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuerName,
                    serialNumber,
                    notBefore,
                    notAfter,
                    subjectName,
                    subjectPublicKeyInfo
            );

            // Sign the certificate
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);

            // Convert to X509Certificate
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .getCertificate(certHolder);

            serialNumberToVoterId.put(serialNumber.toString(), voterId);
            logger.info("Certificate issued for voter {}", voterId);

            return certificate;
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    /**
     * Shares the list of eligible voters with the voting server.
     *
     * @param votingServer The voting server to update
     */

    public void shareEligibleVotersListWithVotingServer(VotingServer votingServer) {
        votingServer.updateEligibleVotersList(new ConcurrentHashMap<>(eligibleVoters));
        logger.info("Eligible voters list shared with Voting Server");
    }

    /**
     * Exports the list of eligible voters to a file.
     *
     * @param filePath The path to save the file
     * @throws IOException If there's an error writing to the file
     */

    public void exportEligibleVotersList(String filePath) throws IOException {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write("Eligible Voters List\n");
            writer.write("Generated: " + Instant.now() + "\n");
            writer.write("Total Eligible Voters: " + eligibleVoters.size() + "\n\n");

            for (String voterId : eligibleVoters.keySet()) {
                writer.write(voterId + "\n");
            }
        }

        logger.info("Eligible voters list exported to {}", filePath);
    }

    /**
     * Revokes a certificate by adding it to the Certificate Revocation List.
     *
     * @param serialNumber The serial number of the certificate to revoke
     * @param reason The reason for revocation
     * @return true if the certificate was revoked, false otherwise
     */

    public boolean revokeCertificate(String serialNumber, String reason) {
        boolean result = crl.revokeCertificate(serialNumber, reason);

        if (result && serialNumberToVoterId.containsKey(serialNumber)) {
            String voterId = serialNumberToVoterId.get(serialNumber);
            removeEligibleVoter(voterId);
        }

        return result;
    }

    public boolean isCertificateRevoked(String serialNumber) {
        return crl.isRevoked(serialNumber);
    }

    /**
     * Gets the Certificate Revocation List.
     *
     * @return The CRL instance
     */

    public CertificateRevocationList getCrl() {
        return crl;
    }

    /**
     * Gets the public key of the Registration Authority.
     *
     * @return The public key
     */

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

}
