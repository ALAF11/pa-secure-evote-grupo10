package core;

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


public class RegistrationAuthority {

    private static final Logger logger = LoggingUtil.getLogger(RegistrationAuthority.class);
    private final KeyPair keyPair;
    private final Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
    private final ElectionManager electionManager;

    public RegistrationAuthority(ElectionManager electionManager) throws NoSuchAlgorithmException {
        this.electionManager = electionManager;
        logger.info("Initializing Registration Authority");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        this.keyPair = keyGen.generateKeyPair();

        logger.info("Registration Authority initialized successfully");
    }

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


    public boolean removeEligibleVoter(String voterId) {
        if (eligibleVoters.remove(voterId) != null) {
            logger.info("Voter {} removed from eligible voters list", voterId);
            return true;
        } else {
            logger.info("Voter {} not found in eligible voters list", voterId);
            return false;
        }
    }

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

            logger.info("Certificate issued for voter {}", voterId);

            return certificate;
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    public void shareEligibleVotersListWithVotingServer(VotingServer votingServer) {
        votingServer.updateEligibleVotersList(new ConcurrentHashMap<>(eligibleVoters));
        logger.info("Eligible voters list shared with Voting Server");
    }

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

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

}
