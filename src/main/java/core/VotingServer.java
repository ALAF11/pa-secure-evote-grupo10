package core;

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

public class VotingServer {

    private static final Logger logger = LoggingUtil.getLogger(VotingServer.class);
    private final Set<String> usedTokens;
    private final PublicKey raPublicKey;
    private PublicKey aaPublicKey;
    private Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
    private final ElectionManager electionManager;

    // Add these fields to track voters who have already voted
    private final Set<String> votedVoters = ConcurrentHashMap.newKeySet();
    private final Map<String, String> tokenToVoterIdMap = new ConcurrentHashMap<>();

    public VotingServer(PublicKey raPublicKey, ElectionManager electionManager) {
        logger.info("Initializing Voting Server");
        this.raPublicKey = raPublicKey;
        this.electionManager = electionManager;
        this.usedTokens = ConcurrentHashMap.newKeySet();
    }

    public VotingServer(PublicKey rapublicKey) {
        this(rapublicKey, new ElectionManager());
    }

    public void updateEligibleVotersList(Map<String, Boolean> updatedList) {
        this.eligibleVoters = new ConcurrentHashMap<>(updatedList);
        logger.info("Eligible voters list updated. Total eligible voters: {}", eligibleVoters.size());
    }

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

            // Associate token with voter ID
            tokenToVoterIdMap.put(token, voterId);

            logger.info("Voter {} authenticated successfully, token issued", voterId);
            return token;
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

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

    public boolean validateToken(String token) {
        return usedTokens.contains(token);
    }

    public void markTokenAsUsed(String token) {
        // Track which voter has voted
        String voterId = tokenToVoterIdMap.remove(token);
        if (voterId != null) {
            votedVoters.add(voterId);
            logger.debug("Voter {} marked as having voted", voterId);
        }

        usedTokens.remove(token);
        logger.debug("Token marked as used");
    }

    public void setAaPublicKey(PublicKey aaPublicKey) {
        this.aaPublicKey = aaPublicKey;
        logger.info("Tallying Authority public key set");
    }

    public PublicKey getAaPublicKey() {
        return aaPublicKey;
    }
}
