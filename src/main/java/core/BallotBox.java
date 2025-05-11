package core;

import crypto.MixNetwork;
import exception.AuthenticationException;
import exception.VoteSubmissionException;
import model.ElectionManager;
import model.ElectionPhase;
import org.slf4j.Logger;
import util.LoggingUtil;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;

public class BallotBox {

    private static final Logger logger = LoggingUtil.getLogger(BallotBox.class);
    private final List<byte[]> encryptedVotes;
    private final Set<String> usedTokens;
    private final VotingServer votingServer;
    private final List<byte[]> voteSignatures; // For non-repudiation
    private final MixNetwork mixNetwork;
    private final ElectionManager electionManager;
    private static final int MAX_RETRIES = 3;

    public BallotBox(VotingServer votingServer, MixNetwork mixNetwork, ElectionManager electionManager) {
        logger.info("Initializing BallotBox");
        this.votingServer = votingServer;
        this.mixNetwork = mixNetwork;
        this.electionManager = electionManager;
        this.encryptedVotes = Collections.synchronizedList(new ArrayList<>());
        this.usedTokens = ConcurrentHashMap.newKeySet();
        this.voteSignatures = Collections.synchronizedList(new ArrayList<>());
    }

    public BallotBox(VotingServer votingServer) {
        this(votingServer,
                new MixNetwork(votingServer.getAaPublicKey()),
                new ElectionManager());
    }

    public synchronized void submitVote(byte[] encryptedVote, String token, byte[] signature) {
        String transactionId = "SUBMIT_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(transactionId);

        // Check election phase
        if (!electionManager.isInPhase(ElectionPhase.VOTING)) {
            logger.warn("Vote rejected: voting is not currently active");
            LoggingUtil.clearTransactionContext();
            throw new VoteSubmissionException("Voting is not currently active");
        }

        // Implement retry logic
        int retryCount = 0;
        boolean submitted = false;

        while (!submitted) {
            try {
                logger.debug("Validating vote submission with token");

                // Check if token is valid
                if (!votingServer.validateToken(token)) {
                    logger.warn("Vote rejected: invalid token");
                    throw new AuthenticationException("Invalid voting token");
                }

                // Check for duplicate token use
                if (usedTokens.contains(token)) {
                    logger.warn("Vote rejected: token has already been used");
                    throw new VoteSubmissionException("Token has already been used");
                }

                // Store vote, signature, and mark token as used
                encryptedVotes.add(encryptedVote);
                voteSignatures.add(signature);
                usedTokens.add(token);
                votingServer.markTokenAsUsed(token);

                logger.info("Vote accepted successfully");
                submitted = true;
            } catch (AuthenticationException | VoteSubmissionException e) {
                // No retry for client errors
                LoggingUtil.clearTransactionContext();
                throw e;
            } catch (Exception e) {
                // Retry for server/network errors
                retryCount++;
                logger.warn("Vote submission attempt {} failed: {}", retryCount, e.getMessage());

                if (retryCount < MAX_RETRIES) {
                    try {
                        wait(100 * (long) Math.pow(2, retryCount));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                } else {
                    LoggingUtil.clearTransactionContext();
                    throw new VoteSubmissionException("Vote submission failed after multiple attempts", e);
                }
            }
        }

        LoggingUtil.clearTransactionContext();
    }

    public byte[] getVoteSignature(int index) {
        if (index < 0 || index >= voteSignatures.size()) {
            throw new IndexOutOfBoundsException("Invalid vote index");
        }

        return voteSignatures.get(index);
    }

    public List<byte[]> getEncryptedVotes() {
        if (electionManager.isInPhase(ElectionPhase.VOTING)) {
            logger.warn("Attempt to access votes during voting phase");
            throw new SecurityException("Votes can only be accessed after voting has ended");
        }

        logger.info("Providing {} encrypted votes for tallying", encryptedVotes.size());

        // Use mix network to anonymize votes before tallying
        return mixNetwork.mixVotes(encryptedVotes);
    }

    public int getVoteCount() {
        return encryptedVotes.size();
    }
}
