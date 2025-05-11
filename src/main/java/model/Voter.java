package model;

import core.BallotBox;
import core.RegistrationAuthority;
import core.VotingServer;
import crypto.CryptoUtils;
import exception.AuthenticationException;
import exception.VoteSubmissionException;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;


public class Voter {

    private static final Logger logger = LoggingUtil.getLogger(Voter.class);
    private final String id;
    private final KeyPair keyPair;
    private X509Certificate certificate;
    private String pemCertificate;
    private PublicKey aaPublicKey;
    private static final int MAX_RETRIES = 3;

    public Voter(String id) throws NoSuchAlgorithmException {
        this.id = id;
        LoggingUtil.setUserContext(id);

        try {
            logger.debug("Creating new voter with ID: {}", id);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            this.keyPair = keyGen.generateKeyPair();

            logger.debug("Key pair generated for voter: {}", id);
        }
        finally {
            LoggingUtil.clearUserContext();
        }
    }

    public void registerWithRA(RegistrationAuthority ra) throws OperatorCreationException, CertificateException {
        String registrationId = "REG_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(registrationId);
        LoggingUtil.setUserContext(id);

        try {
            logger.info("Voter {} requesting certificate from Registration Authority", id);

            int retryCount = 0;
            boolean registered = false;

            while (!registered) {
                try {
                    this.certificate = ra.issueCertificate(this);

                    try {
                        this.pemCertificate = CryptoUtils.encodeCertificateToPEM(certificate);
                        logger.info("Certificate encoded to PEM format for voter {}", id);

                        exportCertificateToFile("voter_" + id + "_cert.pem");
                    }
                    catch (CertificateEncodingException | IOException e) {
                        logger.error("Failed to process PEM certificate: {}", e.getMessage());
                    }

                    registered = true;
                    logger.info("Voter {} registered successfully", id);
                }
                catch (SecurityException e) {
                    // Don't retry for security exception
                    throw e;
                }
                catch (Exception e) {
                    retryCount++;
                    logger.warn("Registration attempt {} failed for voter {}: {}",
                            retryCount, id, e.getMessage());

                    if (retryCount < MAX_RETRIES) {
                        try {
                            Thread.sleep(100 * (long) Math.pow(2, retryCount));
                        }
                        catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    else {
                        throw e;
                    }
                }
            }
        }
        finally {
            LoggingUtil.clearTransactionContext();
            LoggingUtil.clearUserContext();
        }
    }

    public void vote(VotingServer votingServer, BallotBox ballotBox, String choice) throws Exception {
        String voteId = "VOTE_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(voteId);
        LoggingUtil.setUserContext(id);

        try {
            if (certificate == null) {
                throw new IllegalStateException("Voter must be registered before voting");
            }

            if (aaPublicKey == null) {
                throw new IllegalStateException("Tallying Authority public key not set");
            }

            logger.info("Voter {} initiating voting process", id);

            // Create vote hash for non-repudiation
            byte[] voteHash = CryptoUtils.hash(choice.getBytes());
            byte[] signature = CryptoUtils.sign(voteHash, keyPair.getPrivate());

            // Implement retry logic for voting
            int retryCount = 0;
            boolean voted = false;

            while (!voted) {
                try {
                    // Authenticate with voting server
                    String token = votingServer.authenticateVoter(certificate);
                    logger.debug("Voter {} authenticated and received token", id);

                    // Encrypt vote
                    byte[] encryptedVote = CryptoUtils.encryptVote(choice, aaPublicKey);
                    logger.debug("Vote encrypted successfully");

                    // Submit vote to ballot box
                    ballotBox.submitVote(encryptedVote, token, signature);
                    voted = true;
                    logger.info("Voter {} has cast a vote successfully", id);

                } catch (AuthenticationException | VoteSubmissionException e) {
                    throw e;
                } catch (Exception e) {
                    retryCount++;
                    logger.warn("Voting attempt {} failed for voter {}: {}",
                            retryCount, id, e.getMessage());

                    if (retryCount < MAX_RETRIES) {
                        try {
                            Thread.sleep(100 * (long) Math.pow(2, retryCount));
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    } else {
                        throw new VoteSubmissionException("Voting failed after multiple attempts", e);
                    }
                }
            }
        } finally {
            LoggingUtil.clearTransactionContext();
            LoggingUtil.clearUserContext();
        }
    }

    public String getCertificateSerialNumber() {
        if (certificate == null) {
            throw new IllegalStateException("Voter does not have a certificate");
        }

        return certificate.getSerialNumber().toString();
    }

    public void exportCertificateToFile(String filePath) throws IOException {
        if (pemCertificate == null) {
            throw new IllegalStateException("Certificate not available in PEM format");
        }

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(pemCertificate);
        }
        logger.info("Certificate exported to PEM file: {}", filePath);
    }

    public void setAAPublicKey(PublicKey aaPublicKey) {
        this.aaPublicKey = aaPublicKey;
    }


    public String getId() {
        return id;
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

}
