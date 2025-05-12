package core;

import model.KeyShare;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import crypto.CryptoUtils;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TallyingAuthorityTest {

    private TallyingAuthority tallyingAuthority;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        tallyingAuthority = new TallyingAuthority();
    }

    @Test
    @DisplayName("Test initialization creates valid key pair")
    void testInitialization() {
        assertNotNull(tallyingAuthority.getPublicKey(), "Public key should not be null after initialization");
    }

    @Test
    @DisplayName("Test key splitting with valid parameters")
    void testKeySplitting() {
        // Given
        int n = 5; // Total shares
        int k = 3; // Threshold (minimum shares needed)

        // When
        tallyingAuthority.splitKey(n, k);
        List<KeyShare> shares = tallyingAuthority.getKeyShares();

        // Then
        assertEquals(n, shares.size(), "Should create exactly n shares");

        // Verify all shares have expected properties
        for (int i = 0; i < n; i++) {
            KeyShare share = shares.get(i);
            assertEquals(i + 1, share.getX(), "X value should be sequential");
            assertNotNull(share.getY(), "Y value should not be null");
            assertTrue(share.verify(), "Share should verify correctly");
        }
    }

    @Test
    @DisplayName("Test key splitting with invalid parameters (n < k)")
    void testKeySplittingWithInvalidParams() {
        // Given
        int n = 2; // Total shares
        int k = 3; // Threshold (more than total)

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> tallyingAuthority.splitKey(n, k),
                "Should throw IllegalArgumentException when n < k");
    }

    @Test
    @DisplayName("Test vote decryption and tallying with correct vote counts")
    void testDecryptAndTallyVotes() throws Exception {
        // Given
        tallyingAuthority.splitKey(5, 3);
        List<KeyShare> shares = tallyingAuthority.getKeyShares().subList(0, 3);

        // Create test encrypted votes
        List<byte[]> encryptedVotes = new ArrayList<>();
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate2", tallyingAuthority.getPublicKey()));

        // When
        tallyingAuthority.decryptAndTallyVotes(encryptedVotes, shares);

        // Then
        Map<String, Integer> results = tallyingAuthority.getResults();
        assertEquals(2, results.get("Candidate1"), "Candidate1 should have 2 votes");
        assertEquals(1, results.get("Candidate2"), "Candidate2 should have 1 vote");
        assertEquals(3, results.values().stream().mapToInt(Integer::intValue).sum(), "Total votes should match input count");
    }

    @Test
    @DisplayName("Test with insufficient shares for key reconstruction")
    void testWithInsufficientShares() throws Exception {
        // Given
        tallyingAuthority.splitKey(5, 3);
        // Only 1 share when threshold is 3
        List<KeyShare> insufficientShares = tallyingAuthority.getKeyShares().subList(0, 1);

        List<byte[]> encryptedVotes = new ArrayList<>();
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));

        // When/Then
        assertThrows(IllegalArgumentException.class,
                () -> tallyingAuthority.decryptAndTallyVotes(encryptedVotes, insufficientShares),
                "Should throw exception when using fewer shares than threshold");
    }

    @Test
    @DisplayName("Test with empty votes list")
    void testWithEmptyVotesList() throws Exception {
        // Given
        tallyingAuthority.splitKey(5, 3);
        List<KeyShare> shares = tallyingAuthority.getKeyShares().subList(0, 3);
        List<byte[]> emptyVotes = new ArrayList<>();

        // When
        tallyingAuthority.decryptAndTallyVotes(emptyVotes, shares);

        // Then
        Map<String, Integer> results = tallyingAuthority.getResults();
        assertTrue(results.isEmpty(), "Results should be empty when no votes are tallied");
    }

    @Test
    @DisplayName("Test result map reflects correct tallies")
    void testResultMap() throws Exception {
        // Given
        tallyingAuthority.splitKey(5, 3);
        List<KeyShare> shares = tallyingAuthority.getKeyShares().subList(0, 3);

        List<byte[]> encryptedVotes = new ArrayList<>();
        // Multiple votes for different candidates
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate2", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate3", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));

        // When
        tallyingAuthority.decryptAndTallyVotes(encryptedVotes, shares);

        // Then
        Map<String, Integer> results = tallyingAuthority.getResults();
        assertEquals(3, results.get("Candidate1"), "Candidate1 should have 3 votes");
        assertEquals(1, results.get("Candidate2"), "Candidate2 should have 1 vote");
        assertEquals(1, results.get("Candidate3"), "Candidate3 should have 1 vote");
        assertEquals(5, results.values().stream().mapToInt(Integer::intValue).sum(), "Total votes should match input count");
    }

    @Test
    @DisplayName("Test results publication generates expected output")
    void testPublishResults() throws Exception {
        // Given
        tallyingAuthority.splitKey(5, 3);
        List<KeyShare> shares = tallyingAuthority.getKeyShares().subList(0, 3);

        List<byte[]> encryptedVotes = new ArrayList<>();
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate1", tallyingAuthority.getPublicKey()));
        encryptedVotes.add(CryptoUtils.encryptVote("Candidate2", tallyingAuthority.getPublicKey()));

        tallyingAuthority.decryptAndTallyVotes(encryptedVotes, shares);

        // When
        tallyingAuthority.publishResults();

        // Then
        Map<String, Integer> results = tallyingAuthority.getResults();
        assertEquals(1, results.get("Candidate1"), "Published results should show 1 vote for Candidate1");
        assertEquals(1, results.get("Candidate2"), "Published results should show 1 vote for Candidate2");
    }
}
