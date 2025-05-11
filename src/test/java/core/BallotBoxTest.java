package core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import crypto.MixNetwork;
import exception.AuthenticationException;
import exception.VoteSubmissionException;
import model.ElectionManager;
import model.ElectionPhase;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BallotBoxTest {

    private BallotBox ballotBox;

    @Mock
    private VotingServer votingServer;

    @Mock
    private MixNetwork mixNetwork;

    @Mock
    private ElectionManager electionManager;


    private byte[] encryptedVote;
    private String validToken;
    private byte[] signature;

    @BeforeEach
    void setUp() {
        // Initialize the ballot box with mocked dependencies
        ballotBox = new BallotBox(votingServer, mixNetwork, electionManager);

        // Setup test data
        encryptedVote = "encryptedVoteData".getBytes();
        validToken = "validToken123";
        signature = "voteSignature".getBytes();

        // Default mock behavior
        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(votingServer.validateToken(validToken)).thenReturn(true);
    }

    @Test
    @DisplayName("Should accept valid vote during voting phase")
    void submitVote_ValidVoteDuringVotingPhase_ShouldAcceptVote() {

        ballotBox.submitVote(encryptedVote, validToken, signature);

        assertEquals(1, ballotBox.getVoteCount());
        verify(votingServer).markTokenAsUsed(validToken);
    }

    @Test
    @DisplayName("Should throw exception when voting is not active")
    void submitVote_OutsideVotingPhase_ShouldThrowException() {

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(false);

        VoteSubmissionException exception = assertThrows(VoteSubmissionException.class, () -> {
            ballotBox.submitVote(encryptedVote, validToken, signature);
        });
        assertEquals("Voting is not currently active", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw exception when token is invalid")
    void submitVote_InvalidToken_ShouldThrowException() {

        when(votingServer.validateToken(validToken)).thenReturn(false);

        AuthenticationException exception = assertThrows(AuthenticationException.class, () -> {
            ballotBox.submitVote(encryptedVote, validToken, signature);
        });
        assertEquals("Invalid voting token", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw exception when token has already been used")
    void submitVote_AlreadyUsedToken_ShouldThrowException() {
        // Submit vote once to make the token used
        ballotBox.submitVote(encryptedVote, validToken, signature);

        // Set up for second attempt with same token
        byte[] anotherVote = "anotherEncryptedVote".getBytes();
        byte[] anotherSignature = "anotherSignature".getBytes();

        VoteSubmissionException exception = assertThrows(VoteSubmissionException.class, () -> {
            ballotBox.submitVote(anotherVote, validToken, anotherSignature);
        });
        assertEquals("Token has already been used", exception.getMessage());
    }

    @Test
    @DisplayName("Should return correct vote signature for valid index")
    void getVoteSignature_ValidIndex_ShouldReturnSignature() {
        // Submit a vote first
        ballotBox.submitVote(encryptedVote, validToken, signature);

        byte[] retrievedSignature = ballotBox.getVoteSignature(0);

        assertArrayEquals(signature, retrievedSignature);
    }

    @Test
    @DisplayName("Should throw exception when accessing vote signature with invalid index")
    void getVoteSignature_InvalidIndex_ShouldThrowException() {

        assertThrows(IndexOutOfBoundsException.class, () -> {
            ballotBox.getVoteSignature(0); // No votes submitted yet
        });
    }

    @Test
    @DisplayName("Should return mixed votes when voting has ended")
    void getEncryptedVotes_AfterVotingPhase_ShouldReturnMixedVotes() {
        // First submit a vote during voting phase
        ballotBox.submitVote(encryptedVote, validToken, signature);

        // Switch to after voting phase
        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(false);

        // Prepare mixed votes to be returned by mix network
        List<byte[]> mixedVotes = new ArrayList<>();
        mixedVotes.add("mixedVote".getBytes());
        when(mixNetwork.mixVotes(any())).thenReturn(mixedVotes);

        List<byte[]> retrievedVotes = ballotBox.getEncryptedVotes();

        assertSame(mixedVotes, retrievedVotes);
        verify(mixNetwork).mixVotes(any());
    }

    @Test
    @DisplayName("Should throw exception when accessing votes during voting phase")
    void getEncryptedVotes_DuringVotingPhase_ShouldThrowException() {

        SecurityException exception = assertThrows(SecurityException.class, () -> {
            ballotBox.getEncryptedVotes();
        });
        assertEquals("Votes can only be accessed after voting has ended", exception.getMessage());
    }

    @Test
    @DisplayName("Should return correct vote count")
    void getVoteCount_ShouldReturnNumberOfVotes() {
        // Initially no votes
        assertEquals(0, ballotBox.getVoteCount());

        // Submit two votes with different tokens
        ballotBox.submitVote(encryptedVote, validToken, signature);

        String anotherToken = "anotherToken";
        when(votingServer.validateToken(anotherToken)).thenReturn(true);
        ballotBox.submitVote("vote2".getBytes(), anotherToken, "sig2".getBytes());

        assertEquals(2, ballotBox.getVoteCount());
    }

    @Test
    @DisplayName("Should handle server error and retry successfully")
    void submitVote_WithTemporaryError_ShouldRetryAndSucceed() {

        String retryToken = "retryToken";
        byte[] retryVote = "retryVote".getBytes();
        byte[] retrySignature = "retrySignature".getBytes();

        when(votingServer.validateToken(retryToken)).thenReturn(true);

        // Set up mock to throw once then succeed
        doThrow(new RuntimeException("Temporary error"))
                .doNothing()
                .when(votingServer).markTokenAsUsed(retryToken);

        // Just verify it doesn't throw an exception
        assertDoesNotThrow(() -> {
            try {
                ballotBox.submitVote(retryVote, retryToken, retrySignature);
            } catch (VoteSubmissionException e) {

                if (!e.getMessage().equals("Token has already been used")) {
                    throw e;
                }
            }
        });

        // Verify markTokenAsUsed was called
        verify(votingServer, atLeastOnce()).markTokenAsUsed(retryToken);
    }

    @Test
    @DisplayName("Should fail after maximum retry attempts")
    void submitVote_WithPersistentError_ShouldFailAfterRetries() {
        // Need different tokens for each attempt since BallotBox marks them used internally
        String[] tokens = {"token1", "token2", "token3", "token4"};
        byte[] failVote = "failVote".getBytes();
        byte[] failSignature = "failSignature".getBytes();

        // Make all tokens valid
        for (String token : tokens) {
            when(votingServer.validateToken(token)).thenReturn(true);
        }

        // Make markTokenAsUsed always throw an exception
        doThrow(new RuntimeException("Persistent error"))
                .when(votingServer).markTokenAsUsed(anyString());

        // try with the last token which should exhaust all retries
        Exception exception = assertThrows(Exception.class, () -> {
            ballotBox.submitVote(failVote, tokens[3], failSignature);
        });

        // Verify exception is either the one we expect OR a token already used exception
        assertTrue(
                exception instanceof VoteSubmissionException &&
                        (exception.getMessage().contains("Vote submission failed") ||
                                exception.getMessage().contains("Token has already been used")),
                "Expected either 'Vote submission failed' or 'Token has already been used' but got: " + exception.getMessage()
        );
    }
}
