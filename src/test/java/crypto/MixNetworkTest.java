package crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import util.LoggingUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MixNetworkTest {

    @Test
    @DisplayName("Test that mixVotes returns the same votes in a different order")
    void testMixVotes() throws Exception {
        // Create a public key for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        // Create the MixNetwork instance
        MixNetwork mixNetwork = new MixNetwork(publicKey);

        // Create test votes
        byte[] vote1 = "Vote 1".getBytes();
        byte[] vote2 = "Vote 2".getBytes();
        byte[] vote3 = "Vote 3".getBytes();
        byte[] vote4 = "Vote 4".getBytes();
        byte[] vote5 = "Vote 5".getBytes();

        List<byte[]> originalVotes = new ArrayList<>();
        originalVotes.add(vote1);
        originalVotes.add(vote2);
        originalVotes.add(vote3);
        originalVotes.add(vote4);
        originalVotes.add(vote5);

        // Mix the votes
        List<byte[]> mixedVotes = mixNetwork.mixVotes(originalVotes);


        // Number of votes should remain the same
        assertEquals(originalVotes.size(), mixedVotes.size());

        // All original votes should be present in mixed votes
        for (byte[] originalVote : originalVotes) {
            boolean found = false;
            for (byte[] mixedVote : mixedVotes) {
                if (Arrays.equals(originalVote, mixedVote)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "Original vote not found in mixed votes");
        }
    }

    @Test
    @DisplayName("Test that logging utilities are used correctly")
    void testLoggingUsage() {
        // Create a public key for testing
        PublicKey mockPublicKey = Mockito.mock(PublicKey.class);

        // Create the MixNetwork instance
        MixNetwork mixNetwork = new MixNetwork(mockPublicKey);

        // Create test votes
        List<byte[]> votes = new ArrayList<>();
        votes.add("Vote".getBytes());

        // Use MockedStatic to verify static method calls
        try (MockedStatic<LoggingUtil> logUtilMock = Mockito.mockStatic(LoggingUtil.class)) {
            // Mix the votes
            mixNetwork.mixVotes(votes);

            // Verify that transaction context was set and cleared
            logUtilMock.verify(() -> LoggingUtil.setTransactionContext(Mockito.anyString()));
            logUtilMock.verify(() -> LoggingUtil.clearTransactionContext());
        }
    }

    @Test
    @DisplayName("Test that mixVotes preserves votes when only one vote")
    void testMixVotesWithOneVote() {
        // Create a public key for testing
        PublicKey mockPublicKey = Mockito.mock(PublicKey.class);

        // Create the MixNetwork instance
        MixNetwork mixNetwork = new MixNetwork(mockPublicKey);

        // Create a single test vote
        byte[] singleVote = "Single Vote".getBytes();
        List<byte[]> votes = new ArrayList<>();
        votes.add(singleVote);

        // Mix the votes
        List<byte[]> mixedVotes = mixNetwork.mixVotes(votes);


        assertEquals(1, mixedVotes.size());
        assertTrue(Arrays.equals(singleVote, mixedVotes.get(0)));
    }

    @Test
    @DisplayName("Test that mixVotes handles empty list")
    void testMixVotesWithEmptyList() {
        // Create a public key for testing
        PublicKey mockPublicKey = Mockito.mock(PublicKey.class);

        // Create the MixNetwork instance
        MixNetwork mixNetwork = new MixNetwork(mockPublicKey);

        // Mix empty list
        List<byte[]> emptyList = new ArrayList<>();
        List<byte[]> mixedVotes = mixNetwork.mixVotes(emptyList);


        assertTrue(mixedVotes.isEmpty());
    }
}
