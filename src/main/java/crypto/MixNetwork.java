package crypto;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a mix network for anonymizing encrypted votes in the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Taking a collection of encrypted votes</li>
 *     <li>Shuffling them using a secure random algorithm (Fisher-Yates)</li>
 *     <li>Returning the shuffled votes with no way to trace the original order</li>
 * </ul>
 * <p>
 * The mix network ensures voter anonymity by breaking the link between the order
 * in which votes were cast and the order in which they are tallied.
 * <p>
 * Implemented as a Java record for immutability.
 * @param tallyingAuthorityPublicKey The public key of the Tallying Authority
 */

public record MixNetwork(PublicKey tallyingAuthorityPublicKey) {

    private static final Logger logger = LoggingUtil.getLogger(MixNetwork.class);

    /**
     * Mixes (shuffles) a list of encrypted votes to ensure anonymity.
     * <p>
     * The method uses the Fisher-Yates algorithm with a cryptographically secure
     * random number generator to shuffle the votes.
     *
     * @param encryptedVotes The list of encrypted votes to mix
     * @return A new list containing the same votes in a randomly shuffled order
     */

    public List<byte[]> mixVotes(List<byte[]> encryptedVotes) {
        String mixId = "MIX_" + UUID.randomUUID().toString();
        LoggingUtil.setTransactionContext(mixId);

        try {
            logger.info("Mixing {} votes", encryptedVotes.size());

            // Create a copy of the encrypted votes
            List<byte[]> mixedVotes = new ArrayList<>(encryptedVotes);

            // Shuffle the votes using Fisher-Yates algorithm
            SecureRandom random = new SecureRandom();
            for (int i = mixedVotes.size() - 1; i > 0; i--) {
                int j = random.nextInt(i + 1);

                // Swap votes
                byte[] temp = mixedVotes.get(j);
                mixedVotes.set(j, mixedVotes.get(i));
                mixedVotes.set(i, temp);
            }

            logger.info("Vote mixing completed successfully");
            return mixedVotes;
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

}
