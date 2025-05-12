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

/**
 * Represents a voter in the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Generating cryptographic key pairs for voter authentication</li>
 *     <li>Obtaining certificates from the Registration Authority</li>
 *     <li>Authenticating with the Voting Server</li>
 *     <li>Encrypting and casting votes to the Ballot Box</li>
 *     <li>Managing certificate information</li>
 * </ul>
 * <p>
 * The Voter class implements retry logic for both registration and voting
 * operations to handle transient failures.
 */

public class Voter {

    private static final Logger logger = LoggingUtil.getLogger(Voter.class);
    private final String id;
    private final KeyPair keyPair;
    private X509Certificate certificate;
    private String pemCertificate;
    private PublicKey aaPublicKey;
    private static final int MAX_RETRIES = 3;


    /**
     * Constructs a new Voter with the specified ID.
     * <p>
     * This constructor generates an RSA key pair for the voter to use
     * in the registration and voting processes.
     *
     * @param id The unique identifier for this voter.
     * @throws NoSuchAlgorithmException If the RSA algorithm is unavailable.
     */

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

    /**
     * Registers the voter with the Registration Authority to obtain a certificate.
     * <p>
     * This method implements retry logic to handle transient failures.
     * After successful registration, the certificate is encoded in PEM format
     * and exported to a local file.
     *
     * @param  ra The Registration Authority to register with.
     * @throws OperatorCreationException If there is an error creating the certificate.
     * @throws CertificateException If there is a problem with the certificate.
     * @throws SecurityException If registration fails due to a security issue.
     */

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

    /**
     * Casts a vote for a specific candidate.
     * <p>
     * This method:
     * <ol>
     *     <li>Authenticates the voter with the Voting Server and obtains a token.</li>
     *     <li>Encrypts the vote using the Tallying Authority's public key.</li>
     *     <li>Signs a hash of the vote to ensure non-repudiation.</li>
     *     <li>Submits the encrypted vote to the Ballot Box.</li>
     * </ol>
     * Implements retry logic in case of transient failures during voting.
     *
     * @param votingServer The Voting Server used to authenticate the voter.
     * @param ballotBox The Ballot Box to which the vote is submitted.
     * @param choice The candidate selected by the voter.
     * @throws AuthenticationException If authentication with the Voting Server fails.
     * @throws VoteSubmissionException If vote submission fails after retries.
     * @throws IllegalStateException If the voter is not registered or AA public key is not set.
     */

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

    /**
     * Retrieves the serial number of the voter's certificate.
     *
     * @return The certificate serial number as a string.
     * @throws IllegalStateException If the certificate has not been issued yet.
     */

    public String getCertificateSerialNumber() {
        if (certificate == null) {
            throw new IllegalStateException("Voter does not have a certificate");
        }

        return certificate.getSerialNumber().toString();
    }

    /**
     * Exports the voter's PEM-encoded certificate to the specified file path.
     *
     * @param filePath The file path where the PEM certificate should be saved.
     * @throws IOException If an I/O error occurs while writing the file.
     * @throws IllegalStateException If the PEM certificate is not available.
     */

    public void exportCertificateToFile(String filePath) throws IOException {
        if (pemCertificate == null) {
            throw new IllegalStateException("Certificate not available in PEM format");
        }

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(pemCertificate);
        }
        logger.info("Certificate exported to PEM file: {}", filePath);
    }

    /**
     * Sets the Tallying Authority's public key, used for encrypting votes.
     *
     * @param aaPublicKey The public key of the Tallying Authority.
     */

    public void setAaPublicKey(PublicKey aaPublicKey) {
        this.aaPublicKey = aaPublicKey;
    }

     /**
     * Returns the unique identifier of the voter.
     *
     * @return The voter ID.
     */


    public String getId() {
        return id;
    }

    /**
     * Returns the public key associated with the voter.
     *
     * @return The voter's public key.
     */


    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

}
