package crypto;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class MixNetwork {

    private static final Logger logger = LoggingUtil.getLogger(MixNetwork.class);

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
