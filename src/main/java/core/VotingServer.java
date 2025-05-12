package core;

import crypto.CertificateRevocationList;
import exception.AuthenticationException;
import model.ElectionManager;
import model.ElectionPhase;
import util.LoggingUtil;

import org.slf4j.Logger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents the Voting Server in the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Authenticating voters using their certificates</li>
 *     <li>Issuing secure voting tokens to authenticated voters</li>
 *     <li>Preventing duplicate voting by tracking used tokens and
 *     voted voters</li>
 *     <li>Maintaining the list of eligible voters received from the
 *     Registration Authority</li>
 * </ul>
 * <p>
 * The Voting Server operates during the voting phase of an election and
 * interacts with the Registration Authority and Ballot Box.
 */

public class VotingServer {

    private static final Logger logger = LoggingUtil.getLogger(VotingServer.class);
    private final Set<String> usedTokens;
    private final PublicKey raPublicKey;
    private final CertificateRevocationList crl;
    private PublicKey aaPublicKey;
    private Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
    private final ElectionManager electionManager;

    // Add these fields to track voters who have already voted
    private final Set<String> votedVoters = ConcurrentHashMap.newKeySet();

    /**
     * Constructs a new Voting Server with the specified dependencies.
     *
     * @param raPublicKey The public key of the Registration Authority
     * @param electionManager The election Manager for phase control
     * @param crl The Certificate Revocation List
     */

    public VotingServer(PublicKey raPublicKey, ElectionManager electionManager, CertificateRevocationList crl) {
        logger.info("Initializing Voting Server");
        this.raPublicKey = raPublicKey;
        this.electionManager = electionManager;
        this.crl = crl;
        this.usedTokens = ConcurrentHashMap.newKeySet();
    }

    /**
     * Constructs a new Voting Server with default dependencies.
     *
     * @param rapublicKey The Registration Authority's public key
     */

    public VotingServer(PublicKey rapublicKey) {
        this(rapublicKey, new ElectionManager(), new CertificateRevocationList());
    }

    /**
     * Updates the list of eligible voters from the Registration Authority.
     *
     * @param updatedList The updated list of eligible voters
     */

    public void updateEligibleVotersList(Map<String, Boolean> updatedList) {
        this.eligibleVoters = new ConcurrentHashMap<>(updatedList);
        logger.info("Eligible voters list updated. Total eligible voters: {}", eligibleVoters.size());
    }

    /**
     * Authenticates a voter using their certificate.
     * <p>
     * This method can only be called during the voting phase. It checks if the
     * voter is eligible, if they have already voted, if the certificate is revoked,
     * and validates their certificate.
     *
     * @param cert The voter's X.509 certificate
     * @return A voting token if authentication is successful
     * @throws AuthenticationException If authentication fails
     */

    public String authenticateVoter(X509Certificate cert) {
        String transactionId = "AUTH_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(transactionId);

        try {
            // Check if voting is active
            if (!electionManager.isInPhase(ElectionPhase.VOTING)) {
                logger.warn("Authentication failed: voting is not currently active");
                throw new AuthenticationException("Voting is not currently active");
            }

            // Extract voter ID from certificate
            String voterId = extractVoterIdFromCertificate(cert);
            logger.debug("Authenticating voter: {}", voterId);

            // Check if voter has already voted
            if (votedVoters.contains(voterId)) {
                logger.warn("Authentication failed: voter {} has already voted", voterId);
                throw new AuthenticationException("Voter is not eligible to vote");
            }

            // Rest of existing checks
            if (!eligibleVoters.containsKey(voterId)) {
                logger.warn("Authentication failed: voter {} is not eligible", voterId);
                throw new AuthenticationException("Voter is not eligible to vote");
            }

            if (crl.isRevoked(cert)) {
                logger.warn("Authentication failed: certificate for voter {} is revoked", voterId);
                throw new AuthenticationException("Certificate has been revoked");
            }

            try {
                cert.verify(raPublicKey);
                cert.checkValidity();
                logger.debug("Certificate validated successfully");
            } catch (Exception e) {
                logger.warn("Authentication failed: invalid certificate for voter {}", voterId);
                throw new AuthenticationException("Invalid certificate: " + e.getMessage());
            }

            // Generate a secure unique token
            String token = UUID.randomUUID().toString();
            usedTokens.add(token);

            votedVoters.add(voterId);

            logger.info("Voter {} authenticated successfully, token issued", voterId);
            return token;
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    /**
     * Extracts voter ID from certificate subject DN.
     *
     * @param cert The X.509 certificate
     * @return The extracted voter ID
     * @throws IllegalArgumentException if ID extraction fails
     */

    private String extractVoterIdFromCertificate(X509Certificate cert) {
        String subjectDN = cert.getSubjectX500Principal().getName();
        String[] parts = subjectDN.split(",");
        for (String part : parts) {
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }

        throw new IllegalArgumentException("Cannot extract voter ID from certificate");
    }

    /**
     * Validates a voting token.
     *
     * @param token The token to validate
     * @return true if the token is valid, false otherwise
     */

    public boolean validateToken(String token) {
        return usedTokens.contains(token);
    }

    /**
     * Marks a token as used after a vote has been cast.
     *
     * @param token The token to mark as used
     */

    public void markTokenAsUsed(String token) {
        usedTokens.remove(token);
        logger.debug("Token marked as used");
    }

    /**
     * Sets the Tallying Authority's public key.
     *
     * @param aaPublicKey The public key of the Tallying Authority
     */

    public void setAaPublicKey(PublicKey aaPublicKey) {
        this.aaPublicKey = aaPublicKey;
        logger.info("Tallying Authority public key set");
    }

    /**
     * Gets the public key of the Tallying Authority.
     *
     * @return The public key of the Tallying Authority
     */

    public PublicKey getAaPublicKey() {
        return aaPublicKey;
    }
}
